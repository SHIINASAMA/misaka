use super::context::Context;
use super::ScenarioError;
/// 场景函数签名：接收一个上下文，返回 Ok(()) 或 Err(断言/基础设施失败)。
pub type ScenarioFn = Box<dyn Fn(&mut Context) -> Result<(), ScenarioError> + Send>;

pub struct ScenarioDef {
    pub name: &'static str,
    pub run: ScenarioFn,
}
