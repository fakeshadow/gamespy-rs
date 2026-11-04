//! Browser filter grammar with caller-supplied boolean field classification.
use std::cmp::Ordering;
/// A boolean preference shared by searches and sessions. `Any` means an
/// unrestricted search or an unknown session value.
///
/// Equality compares preferences literally. Wildcard matching is deliberately
/// separate: making Any equal both Yes and No would violate Eq's transitivity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Preference {
    Yes,
    No,
    #[default]
    Any,
}

impl Preference {
    /// Parse a numeric wire constraint, or Any when that constraint is absent.
    /// The client's UI wildcard IDs are not wire values: it omits the clause.
    pub fn from_wire(value: Option<&str>) -> Result<Self, &'static str> {
        match value {
            None => Ok(Self::Any),
            Some(value) => Number::parse(value)
                .and_then(|number| number.as_bool())
                .map(Self::from)
                .ok_or("boolean preference must be 0 or 1"),
        }
    }

    /// Directional matching: call request.matches(session). An unrestricted
    /// request accepts unknown values; a concrete request does not.
    pub fn matches(self, actual: Self) -> bool {
        self == Self::Any || self == actual
    }
}

impl From<bool> for Preference {
    fn from(value: bool) -> Self {
        if value { Self::Yes } else { Self::No }
    }
}

fn field_value<'a>(keys: &'a [(String, String)], key: &str) -> Option<&'a str> {
    let mut values = keys.iter().filter(|(name, _)| name == key);
    let (_, value) = values.next()?;
    if values.next().is_some() {
        return None;
    }
    Some(value)
}

#[derive(Debug)]
pub struct Filter(Expr);

#[derive(Debug)]
enum Expr {
    All,
    Boolean(String, Preference),
    Compare(String, String, Operand),
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
}

#[derive(Debug)]
enum Operand {
    Literal(Number),
    Field(String),
}

#[derive(Debug, Clone)]
enum Number {
    Integer(i128),
    Decimal(f64),
}

impl Number {
    fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Integer(0) => Some(false),
            Self::Integer(1) => Some(true),
            Self::Decimal(n) if *n == 0.0 => Some(false),
            Self::Decimal(n) if *n == 1.0 => Some(true),
            _ => None,
        }
    }

    fn parse(text: &str) -> Option<Self> {
        if let Ok(n) = text.parse::<i128>() {
            return Some(Self::Integer(n));
        }
        // No NaN, infinity, exponents, or integer overflow fallback.
        if !text.contains('.')
            || !text
                .bytes()
                .all(|c| c.is_ascii_digit() || b"+-.".contains(&c))
        {
            return None;
        }
        text.parse::<f64>()
            .ok()
            .filter(|n| n.is_finite())
            .map(Self::Decimal)
    }

    fn compare(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (Self::Integer(a), Self::Integer(b)) => Some(a.cmp(b)),
            _ => {
                let float = |n: &Self| match n {
                    Self::Integer(v) => *v as f64,
                    Self::Decimal(v) => *v,
                };
                float(self).partial_cmp(&float(other))
            }
        }
    }
}

impl Filter {
    /// Inspect parsed field references without relying on substring matches.
    pub fn references_field(&self, key: &str) -> bool {
        fn references(expr: &Expr, key: &str) -> bool {
            match expr {
                Expr::All => false,
                Expr::Boolean(field, _) => field == key,
                Expr::Compare(field, _, operand) => {
                    field == key || matches!(operand, Operand::Field(rhs) if rhs == key)
                }
                Expr::And(a, b) | Expr::Or(a, b) => references(a, key) || references(b, key),
            }
        }
        references(&self.0, key)
    }

    /// Empty means no constraints. Omitted fields are never defaulted to zero.
    ///
    /// Every clause is a numeric predicate: without the original title's
    /// boolean dictionary nothing is classified as a [`Preference`], so pass
    /// that dictionary to [`Filter::parse_with_preferences`] when there is one.
    pub fn parse(text: &str) -> Result<Self, &'static str> {
        Self::parse_with_preferences(text, |_| false)
    }

    pub fn parse_with_preferences(
        text: &str,
        preferences: fn(&str) -> bool,
    ) -> Result<Self, &'static str> {
        if text.len() > super::browser::MAX_REQUEST_BYTES {
            return Err("filter too long");
        }
        let mut parser = Parser {
            rest: text.trim(),
            preferences,
        };
        if parser.rest.is_empty() {
            return Ok(Self(Expr::All));
        }
        let expr = parser.expression(0)?;
        if !parser.rest.trim().is_empty() {
            return Err("unsupported filter syntax");
        }
        Ok(Self(expr))
    }

    pub fn matches(&self, keys: &[(String, String)]) -> bool {
        self.matches_with(keys, &|key| {
            Preference::from_wire(field_value(keys, key)).unwrap_or_default()
        })
    }

    /// Use the typed preferences stored at registration; raw fields are
    /// retained for numeric predicates and lossless browser replies.
    pub fn matches_with(
        &self,
        keys: &[(String, String)],
        session: &dyn Fn(&str) -> Preference,
    ) -> bool {
        fn eval(
            expr: &Expr,
            keys: &[(String, String)],
            session: &dyn Fn(&str) -> Preference,
        ) -> bool {
            match expr {
                Expr::All => true,
                Expr::And(a, b) => eval(a, keys, session) && eval(b, keys, session),
                Expr::Or(a, b) => eval(a, keys, session) || eval(b, keys, session),
                Expr::Boolean(key, preference) => preference.matches(session(key)),
                Expr::Compare(key, op, expected) => {
                    let Some(value) = field_value(keys, key) else {
                        return false;
                    };
                    let Some(actual) = Number::parse(value) else {
                        return false;
                    };
                    let expected = match expected {
                        Operand::Literal(number) => number.clone(),
                        Operand::Field(field) => {
                            let Some(number) = field_value(keys, field).and_then(Number::parse)
                            else {
                                return false;
                            };
                            number
                        }
                    };
                    let Some(order) = actual.compare(&expected) else {
                        return false;
                    };
                    match op.as_str() {
                        "=" => order == Ordering::Equal,
                        "!=" | "<>" => order != Ordering::Equal,
                        "<" => order == Ordering::Less,
                        ">" => order == Ordering::Greater,
                        "<=" => order != Ordering::Greater,
                        ">=" => order != Ordering::Less,
                        _ => false,
                    }
                }
            }
        }
        eval(&self.0, keys, session)
    }
}

struct Parser<'a> {
    rest: &'a str,
    preferences: fn(&str) -> bool,
}
impl Parser<'_> {
    fn eat(&mut self, token: &str) -> bool {
        self.rest = self.rest.trim_start();
        if self.rest.starts_with(token) {
            self.rest = &self.rest[token.len()..];
            true
        } else {
            false
        }
    }
    fn expression(&mut self, depth: usize) -> Result<Expr, &'static str> {
        let mut expr = self.conjunction(depth)?;
        while self.eat("OR") {
            expr = Expr::Or(Box::new(expr), Box::new(self.conjunction(depth)?));
        }
        Ok(expr)
    }
    fn conjunction(&mut self, depth: usize) -> Result<Expr, &'static str> {
        let mut expr = self.atom(depth)?;
        while self.eat("AND") {
            expr = Expr::And(Box::new(expr), Box::new(self.atom(depth)?));
        }
        Ok(expr)
    }
    fn atom(&mut self, depth: usize) -> Result<Expr, &'static str> {
        if depth > 32 {
            return Err("filter nesting too deep");
        }
        if self.eat("(") {
            let expr = self.expression(depth + 1)?;
            if !self.eat(")") {
                return Err("missing closing parenthesis");
            }
            return Ok(expr);
        }
        self.rest = self.rest.trim_start();
        let len = self
            .rest
            .bytes()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == b'_')
            .count();
        if len == 0 || self.rest.as_bytes()[0].is_ascii_digit() {
            return Err("missing field name");
        }
        let key = self.rest[..len].to_owned();
        self.rest = &self.rest[len..];
        let op = ["<=", ">=", "!=", "<>", "=", "<", ">"]
            .into_iter()
            .find(|op| self.eat(op))
            .ok_or("missing comparison")?;
        self.rest = self.rest.trim_start();
        // Both sides of a field comparison are numeric host values. Missing,
        // duplicate and malformed values fail closed, including inequality.
        if self
            .rest
            .starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        {
            let len = self
                .rest
                .bytes()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == b'_')
                .count();
            let field = &self.rest[..len];
            if ["nan", "inf", "infinity", "and", "or"]
                .iter()
                .any(|reserved| field.eq_ignore_ascii_case(reserved))
            {
                return Err("invalid numeric value");
            }
            let operand = Operand::Field(field.to_owned());
            self.rest = &self.rest[len..];
            return Ok(Expr::Compare(key, op.to_owned(), operand));
        }
        let len = self
            .rest
            .bytes()
            .take_while(|c| c.is_ascii_digit() || b"+-.".contains(c))
            .count();
        let value = Number::parse(&self.rest[..len]).ok_or("invalid numeric value")?;
        self.rest = &self.rest[len..];
        // Only verified binary settings use Preference. In particular s3
        // (friendly fire), s9 (difficulty), s13 (bot mode) and s30 (host type)
        // have more than two concrete values and remain numeric predicates.
        if (self.preferences)(&key) && matches!(op, "=" | "!=" | "<>") {
            let expected = value.as_bool().ok_or("boolean preference must be 0 or 1")?;
            let preference = Preference::from(if op == "=" { expected } else { !expected });
            return Ok(Expr::Boolean(key, preference));
        }
        Ok(Expr::Compare(key, op.to_owned(), Operand::Literal(value)))
    }
}

#[cfg(test)]
mod tests;
