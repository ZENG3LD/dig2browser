//! Protocol value types for declarative output shaping (Phase C, axis 7).
//!
//! A consumer declares an [`OutputSchema`] (table name + row cardinality +
//! typed, extractor-backed columns) and the engine returns [`RowPage`]s of
//! typed [`Row`]s. This module is **value types only** — encode/decode +
//! bounds + `validate()` for the wire shapes a later read-side request
//! family (e.g. `ReadShaped`) will carry. It defines no `TaskStep`, no
//! `RequestKind` variant, and no IPC request/response pair.
//!
//! See `docs/dig2browser/plans/phase-c-declarative-output-shaping.md`
//! (signed) for the design this codec implements.

use crate::{ProtocolError, MAX_HTML_BYTES, MAX_REQUEST_BYTES, MAX_SELECTOR_BYTES};

/// Upper bound on columns in one [`OutputSchema`], and on the header/row
/// arity of one [`RowPage`].
pub const MAX_SCHEMA_COLUMNS: usize = 128;
/// Upper bound on [`OutputSchema::table_name`].
pub const MAX_TABLE_NAME_BYTES: usize = 128;
/// Upper bound on a [`Column`] name and on a [`RowPage`] header name.
pub const MAX_COLUMN_NAME_BYTES: usize = 128;
/// Upper bound on an [`Extractor::Json`] RFC 6901 pointer. Unlike a
/// selector, an empty pointer (`""`, meaning the document root) is valid.
pub const MAX_JSON_POINTER_BYTES: usize = 1024;
/// Upper bound on an [`Extractor::Regex`] pattern.
pub const MAX_REGEX_PATTERN_BYTES: usize = 1024;
/// Upper bound on a [`CssPick::Attr`] attribute name.
pub const MAX_ATTR_NAME_BYTES: usize = 256;
/// Upper bound on rows returned by one [`RowPage`], mirroring the crate's
/// other per-page bounds (`MAX_TRACE_EVENTS`, `MAX_LIVE_EVENTS`).
pub const MAX_ROWS_PER_PAGE: usize = 1024;
/// Upper bound on a [`Value::Text`] cell. `task`'s script/selector-text
/// bound is the same order of magnitude but private to that module (a
/// different domain — task step text, not an extracted cell), so this is
/// its own bound rather than a reuse.
pub const MAX_VALUE_TEXT_BYTES: usize = 64 * 1024;
/// Upper bound on a [`Value::Blob`] cell. Smaller than `MAX_HTML_BYTES`/
/// `MAX_PNG_BYTES` (whole-document caps) since this bounds one extracted
/// cell, not a captured document.
pub const MAX_VALUE_BLOB_BYTES: usize = 1024 * 1024;

/// Outer bound for an encoded [`OutputSchema`]. A schema declaration is
/// inherently small, so it shares `MAX_REQUEST_BYTES` with `CollectionTask`.
const MAX_OUTPUT_SCHEMA_BYTES: usize = MAX_REQUEST_BYTES;
/// Outer bound for an encoded [`Row`] or [`RowPage`]. Reuses `MAX_HTML_BYTES`
/// as the whole-payload ceiling — the same reuse `live::MAX_LIVE_RESPONSE_BYTES`
/// makes for its event pages.
const MAX_ROW_PAYLOAD_BYTES: usize = MAX_HTML_BYTES;

const OUTPUT_SCHEMA_MAGIC: [u8; 4] = *b"D2XS";
const ROW_MAGIC: [u8; 4] = *b"D2XR";
const ROW_PAGE_MAGIC: [u8; 4] = *b"D2XP";
const SHAPE_SCHEMA_VERSION: u16 = 1;

/// How an [`OutputSchema`] maps captured content to rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cardinality {
    /// One row per captured page/frame; every column extracts from the
    /// whole document.
    PageLevel,
    /// One row per element matched by the root selector; each column's
    /// [`Extractor::Css`] resolves relative to that matched element.
    ItemScope(String),
}

impl Cardinality {
    fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::PageLevel => Ok(()),
            Self::ItemScope(selector) => validate_text(selector, MAX_SELECTOR_BYTES, false),
        }
    }
}

/// Capture metadata a column can extract without touching document content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetaField {
    Url,
    FinalUrl,
    HttpStatus,
    Title,
    ReadyState,
    CapturedAt,
    SourceId,
}

impl MetaField {
    fn to_wire(self) -> u8 {
        match self {
            Self::Url => 1,
            Self::FinalUrl => 2,
            Self::HttpStatus => 3,
            Self::Title => 4,
            Self::ReadyState => 5,
            Self::CapturedAt => 6,
            Self::SourceId => 7,
        }
    }

    fn from_wire(value: u8) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::Url),
            2 => Ok(Self::FinalUrl),
            3 => Ok(Self::HttpStatus),
            4 => Ok(Self::Title),
            5 => Ok(Self::ReadyState),
            6 => Ok(Self::CapturedAt),
            7 => Ok(Self::SourceId),
            _ => Err(ProtocolError::InvalidShapePayload),
        }
    }
}

/// What an [`Extractor::Css`] column pulls from its matched element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CssPick {
    Text,
    Attr(String),
    Html,
    Exists,
}

impl CssPick {
    fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Attr(name) => validate_text(name, MAX_ATTR_NAME_BYTES, false),
            Self::Text | Self::Html | Self::Exists => Ok(()),
        }
    }
}

/// A single column's extraction rule.
#[derive(Debug, Clone, PartialEq)]
pub enum Extractor {
    Meta(MetaField),
    Css { selector: String, pick: CssPick },
    /// RFC 6901 JSON pointer into a JSON payload (live WS/SSE frames, or a
    /// JSON HTTP response).
    Json { pointer: String },
    /// Matched against the row scope's text; `group` selects the capture
    /// group (`0` = whole match).
    Regex { pattern: String, group: u32 },
    Const(Value),
}

impl Extractor {
    fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Meta(_) => Ok(()),
            Self::Css { selector, pick } => {
                validate_text(selector, MAX_SELECTOR_BYTES, false)?;
                pick.validate()
            }
            Self::Json { pointer } => validate_text(pointer, MAX_JSON_POINTER_BYTES, true),
            Self::Regex { pattern, .. } => {
                validate_text(pattern, MAX_REGEX_PATTERN_BYTES, false)
            }
            Self::Const(value) => value.validate(),
        }
    }
}

/// A column's declared SQL-ish cell type. The engine coerces the
/// extractor's raw result to this type per the column's [`OnError`] policy;
/// this protocol layer does not itself enforce that a cell's [`Value`]
/// variant matches its column's `ColumnType` (a `Null` cell is always valid
/// regardless of declared type — see `OnError::Null`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnType {
    Text,
    Integer,
    Real,
    Boolean,
    Timestamp,
    Blob,
}

impl ColumnType {
    fn to_wire(self) -> u8 {
        match self {
            Self::Text => 1,
            Self::Integer => 2,
            Self::Real => 3,
            Self::Boolean => 4,
            Self::Timestamp => 5,
            Self::Blob => 6,
        }
    }

    fn from_wire(value: u8) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::Text),
            2 => Ok(Self::Integer),
            3 => Ok(Self::Real),
            4 => Ok(Self::Boolean),
            5 => Ok(Self::Timestamp),
            6 => Ok(Self::Blob),
            _ => Err(ProtocolError::InvalidShapePayload),
        }
    }
}

/// What happens when a column's extraction or type coercion fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnError {
    Null,
    DropRow,
    Fail,
}

impl OnError {
    fn to_wire(self) -> u8 {
        match self {
            Self::Null => 1,
            Self::DropRow => 2,
            Self::Fail => 3,
        }
    }

    fn from_wire(value: u8) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::Null),
            2 => Ok(Self::DropRow),
            3 => Ok(Self::Fail),
            _ => Err(ProtocolError::InvalidShapePayload),
        }
    }
}

/// One typed cell value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    /// Bounded to `MAX_VALUE_TEXT_BYTES`. Extracted content, so — unlike a
    /// structural field such as a selector — this is not NUL/control-char
    /// filtered.
    Text(String),
    Integer(i64),
    /// Must be finite (`NaN`/`inf` rejected), the same rule `TaskStep::Wheel`
    /// applies to its `f64` fields.
    Real(f64),
    Boolean(bool),
    Timestamp(i64),
    /// Bounded to `MAX_VALUE_BLOB_BYTES`.
    Blob(Vec<u8>),
}

impl Value {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Null | Self::Integer(_) | Self::Boolean(_) | Self::Timestamp(_) => Ok(()),
            Self::Text(text) => {
                if text.len() > MAX_VALUE_TEXT_BYTES {
                    Err(ProtocolError::InvalidShapePayload)
                } else {
                    Ok(())
                }
            }
            Self::Real(number) => {
                if number.is_finite() {
                    Ok(())
                } else {
                    Err(ProtocolError::InvalidShapePayload)
                }
            }
            Self::Blob(bytes) => {
                if bytes.len() > MAX_VALUE_BLOB_BYTES {
                    Err(ProtocolError::InvalidShapePayload)
                } else {
                    Ok(())
                }
            }
        }
    }
}

/// One column's name, declared type, extraction rule, and error policy.
#[derive(Debug, Clone, PartialEq)]
pub struct Column {
    name: String,
    ty: ColumnType,
    extractor: Extractor,
    on_error: OnError,
}

impl Column {
    pub fn new(
        name: String,
        ty: ColumnType,
        extractor: Extractor,
        on_error: OnError,
    ) -> Result<Self, ProtocolError> {
        let column = Self {
            name,
            ty,
            extractor,
            on_error,
        };
        column.validate()?;
        Ok(column)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn ty(&self) -> ColumnType {
        self.ty
    }

    pub fn extractor(&self) -> &Extractor {
        &self.extractor
    }

    pub fn on_error(&self) -> OnError {
        self.on_error
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        validate_text(&self.name, MAX_COLUMN_NAME_BYTES, false)?;
        self.extractor.validate()
    }
}

/// A declared table shape: name, row cardinality, and typed columns.
#[derive(Debug, Clone, PartialEq)]
pub struct OutputSchema {
    table_name: String,
    cardinality: Cardinality,
    columns: Vec<Column>,
}

impl OutputSchema {
    pub fn new(
        table_name: String,
        cardinality: Cardinality,
        columns: Vec<Column>,
    ) -> Result<Self, ProtocolError> {
        let schema = Self {
            table_name,
            cardinality,
            columns,
        };
        schema.validate()?;
        Ok(schema)
    }

    pub fn table_name(&self) -> &str {
        &self.table_name
    }

    pub fn cardinality(&self) -> &Cardinality {
        &self.cardinality
    }

    pub fn columns(&self) -> &[Column] {
        &self.columns
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        validate_text(&self.table_name, MAX_TABLE_NAME_BYTES, false)?;
        if self.columns.is_empty() || self.columns.len() > MAX_SCHEMA_COLUMNS {
            return Err(ProtocolError::InvalidShapePayload);
        }
        if duplicate_column_name(&self.columns) {
            return Err(ProtocolError::InvalidShapePayload);
        }
        for column in &self.columns {
            column.validate()?;
        }
        self.cardinality.validate()
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        let mut output = Vec::new();
        output.extend_from_slice(&OUTPUT_SCHEMA_MAGIC);
        output.extend_from_slice(&SHAPE_SCHEMA_VERSION.to_le_bytes());
        put_string_u16(&mut output, &self.table_name, MAX_TABLE_NAME_BYTES)?;
        encode_cardinality(&mut output, &self.cardinality)?;
        let count =
            u8::try_from(self.columns.len()).map_err(|_| ProtocolError::InvalidShapePayload)?;
        output.push(count);
        for column in &self.columns {
            encode_column(&mut output, column)?;
        }
        if output.len() > MAX_OUTPUT_SCHEMA_BYTES {
            return Err(ProtocolError::InvalidShapePayload);
        }
        Ok(output)
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.len() > MAX_OUTPUT_SCHEMA_BYTES {
            return Err(ProtocolError::InvalidShapePayload);
        }
        let mut input = Input::new(payload);
        if input.bytes(4)? != OUTPUT_SCHEMA_MAGIC || input.u16()? != SHAPE_SCHEMA_VERSION {
            return Err(ProtocolError::InvalidShapePayload);
        }
        let table_name = input.string_u16(MAX_TABLE_NAME_BYTES)?;
        let cardinality = decode_cardinality(&mut input)?;
        let count = usize::from(input.u8()?);
        if count == 0 || count > MAX_SCHEMA_COLUMNS {
            return Err(ProtocolError::InvalidShapePayload);
        }
        let mut columns = Vec::with_capacity(count);
        for _ in 0..count {
            columns.push(decode_column(&mut input)?);
        }
        if !input.is_empty() {
            return Err(ProtocolError::InvalidShapePayload);
        }
        Self::new(table_name, cardinality, columns)
    }
}

/// One row of typed cells. A newtype (not a bare `Vec<Value>` alias) so it
/// carries its own bounded codec, independent of any containing [`RowPage`].
#[derive(Debug, Clone, PartialEq)]
pub struct Row(Vec<Value>);

impl Row {
    pub fn new(values: Vec<Value>) -> Result<Self, ProtocolError> {
        let row = Self(values);
        row.validate()?;
        Ok(row)
    }

    pub fn values(&self) -> &[Value] {
        &self.0
    }

    pub fn into_values(self) -> Vec<Value> {
        self.0
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        if self.0.len() > MAX_SCHEMA_COLUMNS {
            return Err(ProtocolError::InvalidShapePayload);
        }
        for value in &self.0 {
            value.validate()?;
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        let mut output = Vec::new();
        output.extend_from_slice(&ROW_MAGIC);
        output.extend_from_slice(&SHAPE_SCHEMA_VERSION.to_le_bytes());
        encode_row_body(&mut output, self)?;
        if output.len() > MAX_ROW_PAYLOAD_BYTES {
            return Err(ProtocolError::InvalidShapePayload);
        }
        Ok(output)
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.len() > MAX_ROW_PAYLOAD_BYTES {
            return Err(ProtocolError::InvalidShapePayload);
        }
        let mut input = Input::new(payload);
        if input.bytes(4)? != ROW_MAGIC || input.u16()? != SHAPE_SCHEMA_VERSION {
            return Err(ProtocolError::InvalidShapePayload);
        }
        let row = decode_row_body(&mut input)?;
        if !input.is_empty() {
            return Err(ProtocolError::InvalidShapePayload);
        }
        Ok(row)
    }
}

/// An opaque row-continuation cursor for [`RowPage`] paging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShapeCursor(u64);

impl ShapeCursor {
    pub const START: Self = Self(0);

    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

/// One page of shaped rows: a header (column name + declared type, mirroring
/// the originating [`OutputSchema::columns`]) and the rows themselves.
/// `next_cursor` is `Some` exactly when `complete` is `false` — a page
/// either finishes the read (`complete`, no cursor to continue from) or
/// carries a cursor to resume from (not `complete`).
#[derive(Debug, Clone, PartialEq)]
pub struct RowPage {
    columns: Vec<(String, ColumnType)>,
    rows: Vec<Row>,
    next_cursor: Option<ShapeCursor>,
    complete: bool,
}

impl RowPage {
    pub fn new(
        columns: Vec<(String, ColumnType)>,
        rows: Vec<Row>,
        next_cursor: Option<ShapeCursor>,
        complete: bool,
    ) -> Result<Self, ProtocolError> {
        let page = Self {
            columns,
            rows,
            next_cursor,
            complete,
        };
        page.validate()?;
        Ok(page)
    }

    pub fn columns(&self) -> &[(String, ColumnType)] {
        &self.columns
    }

    pub fn rows(&self) -> &[Row] {
        &self.rows
    }

    pub fn next_cursor(&self) -> Option<ShapeCursor> {
        self.next_cursor
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        if self.columns.is_empty() || self.columns.len() > MAX_SCHEMA_COLUMNS {
            return Err(ProtocolError::InvalidShapePayload);
        }
        for (name, _) in &self.columns {
            validate_text(name, MAX_COLUMN_NAME_BYTES, false)?;
        }
        if duplicate_header_name(&self.columns) {
            return Err(ProtocolError::InvalidShapePayload);
        }
        if self.rows.len() > MAX_ROWS_PER_PAGE {
            return Err(ProtocolError::InvalidShapePayload);
        }
        for row in &self.rows {
            row.validate()?;
            if row.0.len() != self.columns.len() {
                return Err(ProtocolError::InvalidShapePayload);
            }
        }
        if self.complete == self.next_cursor.is_some() {
            return Err(ProtocolError::InvalidShapePayload);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        let mut output = Vec::new();
        output.extend_from_slice(&ROW_PAGE_MAGIC);
        output.extend_from_slice(&SHAPE_SCHEMA_VERSION.to_le_bytes());
        let column_count =
            u8::try_from(self.columns.len()).map_err(|_| ProtocolError::InvalidShapePayload)?;
        output.push(column_count);
        for (name, ty) in &self.columns {
            put_string_u16(&mut output, name, MAX_COLUMN_NAME_BYTES)?;
            output.push(ty.to_wire());
        }
        let row_count =
            u16::try_from(self.rows.len()).map_err(|_| ProtocolError::InvalidShapePayload)?;
        output.extend_from_slice(&row_count.to_le_bytes());
        for row in &self.rows {
            encode_row_body(&mut output, row)?;
        }
        output.push(u8::from(self.next_cursor.is_some()));
        output.extend_from_slice(
            &self
                .next_cursor
                .map(ShapeCursor::value)
                .unwrap_or(0)
                .to_le_bytes(),
        );
        output.push(u8::from(self.complete));
        if output.len() > MAX_ROW_PAYLOAD_BYTES {
            return Err(ProtocolError::InvalidShapePayload);
        }
        Ok(output)
    }

    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.len() > MAX_ROW_PAYLOAD_BYTES {
            return Err(ProtocolError::InvalidShapePayload);
        }
        let mut input = Input::new(payload);
        if input.bytes(4)? != ROW_PAGE_MAGIC || input.u16()? != SHAPE_SCHEMA_VERSION {
            return Err(ProtocolError::InvalidShapePayload);
        }
        let column_count = usize::from(input.u8()?);
        if column_count == 0 || column_count > MAX_SCHEMA_COLUMNS {
            return Err(ProtocolError::InvalidShapePayload);
        }
        let mut columns = Vec::with_capacity(column_count);
        for _ in 0..column_count {
            let name = input.string_u16(MAX_COLUMN_NAME_BYTES)?;
            let ty = ColumnType::from_wire(input.u8()?)?;
            columns.push((name, ty));
        }
        let row_count = usize::from(input.u16()?);
        if row_count > MAX_ROWS_PER_PAGE {
            return Err(ProtocolError::InvalidShapePayload);
        }
        let mut rows = Vec::with_capacity(row_count);
        for _ in 0..row_count {
            rows.push(decode_row_body(&mut input)?);
        }
        let has_cursor = match input.u8()? {
            0 => false,
            1 => true,
            _ => return Err(ProtocolError::InvalidShapePayload),
        };
        let cursor_value = input.u64()?;
        let next_cursor = if has_cursor {
            Some(ShapeCursor::new(cursor_value))
        } else {
            if cursor_value != 0 {
                return Err(ProtocolError::InvalidShapePayload);
            }
            None
        };
        let complete = match input.u8()? {
            0 => false,
            1 => true,
            _ => return Err(ProtocolError::InvalidShapePayload),
        };
        if !input.is_empty() {
            return Err(ProtocolError::InvalidShapePayload);
        }
        Self::new(columns, rows, next_cursor, complete)
    }
}

fn duplicate_column_name(columns: &[Column]) -> bool {
    let mut seen: Vec<&str> = Vec::new();
    for column in columns {
        if seen.contains(&column.name.as_str()) {
            return true;
        }
        seen.push(&column.name);
    }
    false
}

fn duplicate_header_name(columns: &[(String, ColumnType)]) -> bool {
    let mut seen: Vec<&str> = Vec::new();
    for (name, _) in columns {
        if seen.contains(&name.as_str()) {
            return true;
        }
        seen.push(name);
    }
    false
}

fn encode_cardinality(
    output: &mut Vec<u8>,
    cardinality: &Cardinality,
) -> Result<(), ProtocolError> {
    cardinality.validate()?;
    match cardinality {
        Cardinality::PageLevel => output.push(1),
        Cardinality::ItemScope(selector) => {
            output.push(2);
            put_string_u16(output, selector, MAX_SELECTOR_BYTES)?;
        }
    }
    Ok(())
}

fn decode_cardinality(input: &mut Input<'_>) -> Result<Cardinality, ProtocolError> {
    let cardinality = match input.u8()? {
        1 => Cardinality::PageLevel,
        2 => Cardinality::ItemScope(input.string_u16(MAX_SELECTOR_BYTES)?),
        _ => return Err(ProtocolError::InvalidShapePayload),
    };
    cardinality.validate()?;
    Ok(cardinality)
}

fn encode_meta_field(output: &mut Vec<u8>, field: MetaField) {
    output.push(field.to_wire());
}

fn decode_meta_field(input: &mut Input<'_>) -> Result<MetaField, ProtocolError> {
    MetaField::from_wire(input.u8()?)
}

fn encode_css_pick(output: &mut Vec<u8>, pick: &CssPick) -> Result<(), ProtocolError> {
    pick.validate()?;
    match pick {
        CssPick::Text => output.push(1),
        CssPick::Attr(name) => {
            output.push(2);
            put_string_u16(output, name, MAX_ATTR_NAME_BYTES)?;
        }
        CssPick::Html => output.push(3),
        CssPick::Exists => output.push(4),
    }
    Ok(())
}

fn decode_css_pick(input: &mut Input<'_>) -> Result<CssPick, ProtocolError> {
    let pick = match input.u8()? {
        1 => CssPick::Text,
        2 => CssPick::Attr(input.string_u16(MAX_ATTR_NAME_BYTES)?),
        3 => CssPick::Html,
        4 => CssPick::Exists,
        _ => return Err(ProtocolError::InvalidShapePayload),
    };
    pick.validate()?;
    Ok(pick)
}

fn encode_value(output: &mut Vec<u8>, value: &Value) -> Result<(), ProtocolError> {
    value.validate()?;
    match value {
        Value::Null => output.push(1),
        Value::Text(text) => {
            output.push(2);
            put_string_u32(output, text, MAX_VALUE_TEXT_BYTES)?;
        }
        Value::Integer(number) => {
            output.push(3);
            output.extend_from_slice(&number.to_le_bytes());
        }
        Value::Real(number) => {
            output.push(4);
            output.extend_from_slice(&number.to_le_bytes());
        }
        Value::Boolean(flag) => {
            output.push(5);
            output.push(u8::from(*flag));
        }
        Value::Timestamp(number) => {
            output.push(6);
            output.extend_from_slice(&number.to_le_bytes());
        }
        Value::Blob(bytes) => {
            output.push(7);
            put_bytes_u32(output, bytes, MAX_VALUE_BLOB_BYTES)?;
        }
    }
    Ok(())
}

fn decode_value(input: &mut Input<'_>) -> Result<Value, ProtocolError> {
    let value = match input.u8()? {
        1 => Value::Null,
        2 => Value::Text(input.string_u32(MAX_VALUE_TEXT_BYTES)?),
        3 => Value::Integer(input.i64()?),
        4 => Value::Real(input.f64()?),
        5 => Value::Boolean(match input.u8()? {
            0 => false,
            1 => true,
            _ => return Err(ProtocolError::InvalidShapePayload),
        }),
        6 => Value::Timestamp(input.i64()?),
        7 => Value::Blob(input.bytes_u32(MAX_VALUE_BLOB_BYTES)?.to_vec()),
        _ => return Err(ProtocolError::InvalidShapePayload),
    };
    value.validate()?;
    Ok(value)
}

fn encode_extractor(output: &mut Vec<u8>, extractor: &Extractor) -> Result<(), ProtocolError> {
    extractor.validate()?;
    match extractor {
        Extractor::Meta(field) => {
            output.push(1);
            encode_meta_field(output, *field);
        }
        Extractor::Css { selector, pick } => {
            output.push(2);
            put_string_u16(output, selector, MAX_SELECTOR_BYTES)?;
            encode_css_pick(output, pick)?;
        }
        Extractor::Json { pointer } => {
            output.push(3);
            put_string_u16(output, pointer, MAX_JSON_POINTER_BYTES)?;
        }
        Extractor::Regex { pattern, group } => {
            output.push(4);
            put_string_u16(output, pattern, MAX_REGEX_PATTERN_BYTES)?;
            output.extend_from_slice(&group.to_le_bytes());
        }
        Extractor::Const(value) => {
            output.push(5);
            encode_value(output, value)?;
        }
    }
    Ok(())
}

fn decode_extractor(input: &mut Input<'_>) -> Result<Extractor, ProtocolError> {
    let extractor = match input.u8()? {
        1 => Extractor::Meta(decode_meta_field(input)?),
        2 => Extractor::Css {
            selector: input.string_u16(MAX_SELECTOR_BYTES)?,
            pick: decode_css_pick(input)?,
        },
        3 => Extractor::Json {
            pointer: input.string_u16(MAX_JSON_POINTER_BYTES)?,
        },
        4 => Extractor::Regex {
            pattern: input.string_u16(MAX_REGEX_PATTERN_BYTES)?,
            group: input.u32()?,
        },
        5 => Extractor::Const(decode_value(input)?),
        _ => return Err(ProtocolError::InvalidShapePayload),
    };
    extractor.validate()?;
    Ok(extractor)
}

fn encode_column(output: &mut Vec<u8>, column: &Column) -> Result<(), ProtocolError> {
    column.validate()?;
    put_string_u16(output, &column.name, MAX_COLUMN_NAME_BYTES)?;
    output.push(column.ty.to_wire());
    output.push(column.on_error.to_wire());
    encode_extractor(output, &column.extractor)
}

fn decode_column(input: &mut Input<'_>) -> Result<Column, ProtocolError> {
    let name = input.string_u16(MAX_COLUMN_NAME_BYTES)?;
    let ty = ColumnType::from_wire(input.u8()?)?;
    let on_error = OnError::from_wire(input.u8()?)?;
    let extractor = decode_extractor(input)?;
    Column::new(name, ty, extractor, on_error)
}

fn encode_row_body(output: &mut Vec<u8>, row: &Row) -> Result<(), ProtocolError> {
    row.validate()?;
    let count = u8::try_from(row.0.len()).map_err(|_| ProtocolError::InvalidShapePayload)?;
    output.push(count);
    for value in &row.0 {
        encode_value(output, value)?;
    }
    Ok(())
}

fn decode_row_body(input: &mut Input<'_>) -> Result<Row, ProtocolError> {
    let count = usize::from(input.u8()?);
    if count > MAX_SCHEMA_COLUMNS {
        return Err(ProtocolError::InvalidShapePayload);
    }
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(decode_value(input)?);
    }
    Row::new(values)
}

fn validate_text(value: &str, maximum: usize, allow_empty: bool) -> Result<(), ProtocolError> {
    if (!allow_empty && value.is_empty()) || value.len() > maximum || value.contains('\0') {
        return Err(ProtocolError::InvalidShapePayload);
    }
    Ok(())
}

fn put_string_u16(output: &mut Vec<u8>, value: &str, max_len: usize) -> Result<(), ProtocolError> {
    if value.len() > max_len {
        return Err(ProtocolError::InvalidShapePayload);
    }
    let len = u16::try_from(value.len()).map_err(|_| ProtocolError::InvalidShapePayload)?;
    output.extend_from_slice(&len.to_le_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn put_string_u32(output: &mut Vec<u8>, value: &str, max_len: usize) -> Result<(), ProtocolError> {
    if value.len() > max_len {
        return Err(ProtocolError::InvalidShapePayload);
    }
    let len = u32::try_from(value.len()).map_err(|_| ProtocolError::InvalidShapePayload)?;
    output.extend_from_slice(&len.to_le_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn put_bytes_u32(output: &mut Vec<u8>, value: &[u8], max_len: usize) -> Result<(), ProtocolError> {
    if value.len() > max_len {
        return Err(ProtocolError::InvalidShapePayload);
    }
    let len = u32::try_from(value.len()).map_err(|_| ProtocolError::InvalidShapePayload)?;
    output.extend_from_slice(&len.to_le_bytes());
    output.extend_from_slice(value);
    Ok(())
}

struct Input<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Input<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn bytes(&mut self, len: usize) -> Result<&'a [u8], ProtocolError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(ProtocolError::InvalidShapePayload)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ProtocolError::InvalidShapePayload)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, ProtocolError> {
        Ok(self.bytes(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ProtocolError> {
        Ok(u16::from_le_bytes(self.bytes(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, ProtocolError> {
        Ok(u32::from_le_bytes(self.bytes(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, ProtocolError> {
        Ok(u64::from_le_bytes(self.bytes(8)?.try_into().unwrap()))
    }

    fn i64(&mut self) -> Result<i64, ProtocolError> {
        Ok(i64::from_le_bytes(self.bytes(8)?.try_into().unwrap()))
    }

    fn f64(&mut self) -> Result<f64, ProtocolError> {
        Ok(f64::from_le_bytes(self.bytes(8)?.try_into().unwrap()))
    }

    fn string_u16(&mut self, max_len: usize) -> Result<String, ProtocolError> {
        let len = usize::from(self.u16()?);
        if len > max_len {
            return Err(ProtocolError::InvalidShapePayload);
        }
        std::str::from_utf8(self.bytes(len)?)
            .map(str::to_owned)
            .map_err(|_| ProtocolError::InvalidShapePayload)
    }

    fn string_u32(&mut self, max_len: usize) -> Result<String, ProtocolError> {
        let len = usize::try_from(self.u32()?).map_err(|_| ProtocolError::InvalidShapePayload)?;
        if len > max_len {
            return Err(ProtocolError::InvalidShapePayload);
        }
        std::str::from_utf8(self.bytes(len)?)
            .map(str::to_owned)
            .map_err(|_| ProtocolError::InvalidShapePayload)
    }

    fn bytes_u32(&mut self, max_len: usize) -> Result<&'a [u8], ProtocolError> {
        let len = usize::try_from(self.u32()?).map_err(|_| ProtocolError::InvalidShapePayload)?;
        if len > max_len {
            return Err(ProtocolError::InvalidShapePayload);
        }
        self.bytes(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_columns() -> Vec<Column> {
        vec![
            Column::new(
                "url".to_owned(),
                ColumnType::Text,
                Extractor::Meta(MetaField::Url),
                OnError::Null,
            )
            .expect("meta column"),
            Column::new(
                "title".to_owned(),
                ColumnType::Text,
                Extractor::Css {
                    selector: "h1".to_owned(),
                    pick: CssPick::Text,
                },
                OnError::Null,
            )
            .expect("css text column"),
            Column::new(
                "link".to_owned(),
                ColumnType::Text,
                Extractor::Css {
                    selector: "a".to_owned(),
                    pick: CssPick::Attr("href".to_owned()),
                },
                OnError::DropRow,
            )
            .expect("css attr column"),
            Column::new(
                "summary_html".to_owned(),
                ColumnType::Text,
                Extractor::Css {
                    selector: ".summary".to_owned(),
                    pick: CssPick::Html,
                },
                OnError::Null,
            )
            .expect("css html column"),
            Column::new(
                "has_badge".to_owned(),
                ColumnType::Boolean,
                Extractor::Css {
                    selector: ".badge".to_owned(),
                    pick: CssPick::Exists,
                },
                OnError::Null,
            )
            .expect("css exists column"),
            Column::new(
                "price".to_owned(),
                ColumnType::Real,
                Extractor::Json {
                    pointer: "/offer/price".to_owned(),
                },
                OnError::Fail,
            )
            .expect("json column"),
            Column::new(
                "sku".to_owned(),
                ColumnType::Text,
                Extractor::Regex {
                    pattern: r"SKU-(\d+)".to_owned(),
                    group: 1,
                },
                OnError::Null,
            )
            .expect("regex column"),
            Column::new(
                "source".to_owned(),
                ColumnType::Text,
                Extractor::Const(Value::Text("catalog-crawl".to_owned())),
                OnError::Null,
            )
            .expect("const column"),
        ]
    }

    #[test]
    fn output_schema_round_trips_page_level_with_every_extractor_variant() {
        let schema = OutputSchema::new(
            "products".to_owned(),
            Cardinality::PageLevel,
            sample_columns(),
        )
        .expect("valid schema");

        let encoded = schema.encode().expect("encode schema");
        assert_eq!(&encoded[..4], b"D2XS");
        let decoded = OutputSchema::decode(&encoded).expect("decode schema");
        assert_eq!(decoded, schema);
        assert_eq!(decoded.table_name(), "products");
        assert_eq!(decoded.columns().len(), 8);
    }

    #[test]
    fn output_schema_round_trips_item_scope_cardinality() {
        let schema = OutputSchema::new(
            "product_cards".to_owned(),
            Cardinality::ItemScope(".product-card".to_owned()),
            vec![Column::new(
                "name".to_owned(),
                ColumnType::Text,
                Extractor::Css {
                    selector: ".name".to_owned(),
                    pick: CssPick::Text,
                },
                OnError::Null,
            )
            .expect("column")],
        )
        .expect("valid schema");

        let encoded = schema.encode().expect("encode schema");
        let decoded = OutputSchema::decode(&encoded).expect("decode schema");
        assert_eq!(decoded, schema);
        assert_eq!(
            decoded.cardinality(),
            &Cardinality::ItemScope(".product-card".to_owned())
        );
    }

    #[test]
    fn meta_field_round_trips_all_variants() {
        let fields = [
            MetaField::Url,
            MetaField::FinalUrl,
            MetaField::HttpStatus,
            MetaField::Title,
            MetaField::ReadyState,
            MetaField::CapturedAt,
            MetaField::SourceId,
        ];
        for field in fields {
            let mut output = Vec::new();
            encode_meta_field(&mut output, field);
            let mut input = Input::new(&output);
            assert_eq!(decode_meta_field(&mut input).unwrap(), field);
            assert!(input.is_empty());
        }
    }

    #[test]
    fn css_pick_round_trips_all_variants() {
        let picks = [
            CssPick::Text,
            CssPick::Attr("data-id".to_owned()),
            CssPick::Html,
            CssPick::Exists,
        ];
        for pick in picks {
            let mut output = Vec::new();
            encode_css_pick(&mut output, &pick).expect("encode pick");
            let mut input = Input::new(&output);
            assert_eq!(decode_css_pick(&mut input).unwrap(), pick);
            assert!(input.is_empty());
        }
    }

    #[test]
    fn column_type_and_on_error_round_trip_all_variants() {
        for ty in [
            ColumnType::Text,
            ColumnType::Integer,
            ColumnType::Real,
            ColumnType::Boolean,
            ColumnType::Timestamp,
            ColumnType::Blob,
        ] {
            assert_eq!(ColumnType::from_wire(ty.to_wire()).unwrap(), ty);
        }
        for on_error in [OnError::Null, OnError::DropRow, OnError::Fail] {
            assert_eq!(OnError::from_wire(on_error.to_wire()).unwrap(), on_error);
        }
        assert!(ColumnType::from_wire(u8::MAX).is_err());
        assert!(OnError::from_wire(u8::MAX).is_err());
    }

    #[test]
    fn value_round_trips_all_variants() {
        let values = vec![
            Value::Null,
            Value::Text("hello world".to_owned()),
            Value::Integer(-42),
            Value::Real(3.5),
            Value::Boolean(true),
            Value::Timestamp(1_784_500_000_000),
            Value::Blob(vec![1, 2, 3, 4, 5]),
        ];
        for value in values {
            let mut output = Vec::new();
            encode_value(&mut output, &value).expect("encode value");
            let mut input = Input::new(&output);
            assert_eq!(decode_value(&mut input).unwrap(), value);
            assert!(input.is_empty());
        }
    }

    #[test]
    fn value_real_rejects_non_finite() {
        assert!(Value::Real(f64::NAN).validate().is_err());
        assert!(Value::Real(f64::INFINITY).validate().is_err());
        assert!(Value::Real(f64::NEG_INFINITY).validate().is_err());
        assert!(Value::Real(0.0).validate().is_ok());
    }

    #[test]
    fn row_round_trips_including_empty_row() {
        let row = Row::new(vec![
            Value::Text("acme".to_owned()),
            Value::Integer(7),
            Value::Null,
        ])
        .expect("valid row");
        let encoded = row.encode().expect("encode row");
        assert_eq!(&encoded[..4], b"D2XR");
        assert_eq!(Row::decode(&encoded).unwrap(), row);

        let empty = Row::new(Vec::new()).expect("empty row is valid");
        let encoded_empty = empty.encode().expect("encode empty row");
        assert_eq!(Row::decode(&encoded_empty).unwrap(), empty);
    }

    #[test]
    fn row_page_round_trips_incomplete_and_complete_pages() {
        let columns = vec![
            ("name".to_owned(), ColumnType::Text),
            ("price".to_owned(), ColumnType::Real),
        ];
        let rows = vec![
            Row::new(vec![Value::Text("widget".to_owned()), Value::Real(9.99)]).unwrap(),
            Row::new(vec![Value::Null, Value::Real(1.5)]).unwrap(),
        ];
        let incomplete = RowPage::new(
            columns.clone(),
            rows.clone(),
            Some(ShapeCursor::new(2)),
            false,
        )
        .expect("incomplete page");
        let encoded = incomplete.encode().expect("encode page");
        assert_eq!(&encoded[..4], b"D2XP");
        let decoded = RowPage::decode(&encoded).expect("decode page");
        assert_eq!(decoded, incomplete);
        assert_eq!(decoded.next_cursor(), Some(ShapeCursor::new(2)));
        assert!(!decoded.is_complete());

        let complete = RowPage::new(columns, rows, None, true).expect("complete page");
        let encoded = complete.encode().expect("encode complete page");
        let decoded = RowPage::decode(&encoded).expect("decode complete page");
        assert_eq!(decoded, complete);
        assert_eq!(decoded.next_cursor(), None);
        assert!(decoded.is_complete());
    }

    #[test]
    fn row_page_requires_cursor_iff_incomplete() {
        let columns = vec![("name".to_owned(), ColumnType::Text)];
        let rows = vec![Row::new(vec![Value::Text("x".to_owned())]).unwrap()];
        assert!(RowPage::new(columns.clone(), rows.clone(), None, false).is_err());
        assert!(RowPage::new(
            columns,
            rows,
            Some(ShapeCursor::new(1)),
            true
        )
        .is_err());
    }

    #[test]
    fn row_page_rejects_row_arity_mismatch() {
        let columns = vec![("name".to_owned(), ColumnType::Text)];
        let mismatched_row =
            Row::new(vec![Value::Text("x".to_owned()), Value::Integer(1)]).unwrap();
        assert!(RowPage::new(columns, vec![mismatched_row], None, true).is_err());
    }

    #[test]
    fn output_schema_validate_rejects_empty_table_name() {
        assert!(OutputSchema::new(
            String::new(),
            Cardinality::PageLevel,
            sample_columns(),
        )
        .is_err());
    }

    #[test]
    fn output_schema_validate_rejects_zero_columns() {
        assert!(
            OutputSchema::new("t".to_owned(), Cardinality::PageLevel, Vec::new()).is_err()
        );
    }

    #[test]
    fn output_schema_validate_rejects_duplicate_column_names() {
        let columns = vec![
            Column::new(
                "name".to_owned(),
                ColumnType::Text,
                Extractor::Meta(MetaField::Title),
                OnError::Null,
            )
            .unwrap(),
            Column::new(
                "name".to_owned(),
                ColumnType::Text,
                Extractor::Meta(MetaField::Url),
                OnError::Null,
            )
            .unwrap(),
        ];
        assert!(OutputSchema::new("t".to_owned(), Cardinality::PageLevel, columns).is_err());
    }

    #[test]
    fn output_schema_validate_rejects_too_many_columns() {
        let columns: Vec<Column> = (0..=MAX_SCHEMA_COLUMNS)
            .map(|index| {
                Column::new(
                    format!("col-{index}"),
                    ColumnType::Text,
                    Extractor::Meta(MetaField::Url),
                    OnError::Null,
                )
                .expect("valid column")
            })
            .collect();
        assert!(OutputSchema::new("t".to_owned(), Cardinality::PageLevel, columns).is_err());
    }

    #[test]
    fn output_schema_validate_rejects_empty_item_scope_selector() {
        assert!(OutputSchema::new(
            "t".to_owned(),
            Cardinality::ItemScope(String::new()),
            sample_columns(),
        )
        .is_err());
    }

    #[test]
    fn column_and_extractor_bounds_fail_closed() {
        assert!(Column::new(
            "a".repeat(MAX_COLUMN_NAME_BYTES + 1),
            ColumnType::Text,
            Extractor::Meta(MetaField::Url),
            OnError::Null,
        )
        .is_err());
        assert!(Column::new(
            "name".to_owned(),
            ColumnType::Text,
            Extractor::Css {
                selector: "a".repeat(MAX_SELECTOR_BYTES + 1),
                pick: CssPick::Text,
            },
            OnError::Null,
        )
        .is_err());
        assert!(Column::new(
            "name".to_owned(),
            ColumnType::Text,
            Extractor::Css {
                selector: "a".to_owned(),
                pick: CssPick::Attr("x".repeat(MAX_ATTR_NAME_BYTES + 1)),
            },
            OnError::Null,
        )
        .is_err());
        assert!(Column::new(
            "name".to_owned(),
            ColumnType::Text,
            Extractor::Json {
                pointer: "x".repeat(MAX_JSON_POINTER_BYTES + 1),
            },
            OnError::Null,
        )
        .is_err());
        assert!(Column::new(
            "name".to_owned(),
            ColumnType::Text,
            Extractor::Regex {
                pattern: "x".repeat(MAX_REGEX_PATTERN_BYTES + 1),
                group: 0,
            },
            OnError::Null,
        )
        .is_err());
        // An empty JSON pointer (document root, RFC 6901) is valid, unlike an
        // empty selector.
        assert!(Column::new(
            "name".to_owned(),
            ColumnType::Text,
            Extractor::Json {
                pointer: String::new(),
            },
            OnError::Null,
        )
        .is_ok());
        // An empty regex pattern is rejected (not a meaningful match rule).
        assert!(Column::new(
            "name".to_owned(),
            ColumnType::Text,
            Extractor::Regex {
                pattern: String::new(),
                group: 0,
            },
            OnError::Null,
        )
        .is_err());
    }

    #[test]
    fn value_text_and_blob_bounds_fail_closed() {
        assert!(Value::Text("x".repeat(MAX_VALUE_TEXT_BYTES + 1))
            .validate()
            .is_err());
        assert!(Value::Text("x".repeat(MAX_VALUE_TEXT_BYTES))
            .validate()
            .is_ok());
        assert!(Value::Blob(vec![0; MAX_VALUE_BLOB_BYTES + 1])
            .validate()
            .is_err());
        assert!(Value::Blob(vec![0; MAX_VALUE_BLOB_BYTES])
            .validate()
            .is_ok());
    }

    #[test]
    fn output_schema_decode_rejects_oversized_declared_table_name_length() {
        let schema = OutputSchema::new(
            "products".to_owned(),
            Cardinality::PageLevel,
            sample_columns(),
        )
        .expect("valid schema");
        let mut encoded = schema.encode().expect("encode schema");
        // Byte layout: magic(4) + version(2) -> table_name length prefix at 6..8.
        let oversized = u16::try_from(MAX_TABLE_NAME_BYTES + 1).unwrap();
        encoded[6..8].copy_from_slice(&oversized.to_le_bytes());
        assert!(OutputSchema::decode(&encoded).is_err());
    }

    #[test]
    fn row_page_decode_rejects_declared_row_count_over_bound() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ROW_PAGE_MAGIC);
        bytes.extend_from_slice(&SHAPE_SCHEMA_VERSION.to_le_bytes());
        bytes.push(1); // one column
        put_string_u16(&mut bytes, "value", MAX_COLUMN_NAME_BYTES).unwrap();
        bytes.push(ColumnType::Text.to_wire());
        let over_bound = u16::try_from(MAX_ROWS_PER_PAGE + 1).unwrap();
        bytes.extend_from_slice(&over_bound.to_le_bytes());
        assert!(RowPage::decode(&bytes).is_err());
    }

    #[test]
    fn row_decode_rejects_declared_value_count_over_schema_column_bound() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ROW_MAGIC);
        bytes.extend_from_slice(&SHAPE_SCHEMA_VERSION.to_le_bytes());
        // MAX_SCHEMA_COLUMNS fits a u8, so exceeding it wraps; use a value
        // just past the bound that still fits u8 (bound is 128).
        bytes.push(u8::try_from(MAX_SCHEMA_COLUMNS + 1).unwrap());
        assert!(Row::decode(&bytes).is_err());
    }

    #[test]
    fn unknown_extractor_and_value_tags_fail_closed_on_decode() {
        let mut output = Vec::new();
        output.push(u8::MAX);
        let mut input = Input::new(&output);
        assert!(decode_extractor(&mut input).is_err());

        let mut output = Vec::new();
        output.push(u8::MAX);
        let mut input = Input::new(&output);
        assert!(decode_value(&mut input).is_err());

        let mut output = Vec::new();
        output.push(u8::MAX);
        let mut input = Input::new(&output);
        assert!(decode_cardinality(&mut input).is_err());
    }
}
