function runExpression(req) {
  return eval(req.query.expr);
}

module.exports = { runExpression };
