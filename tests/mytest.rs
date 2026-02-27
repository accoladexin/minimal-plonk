// 1. 定义一个 Trait (类似 ark_ec::pairing::Pairing)
trait Animal {
    // 定义一个关联类型，即“食物类型”
    // 这里只是个占位符，具体是什么由实现类决定
    type Food;

    fn eat(&self, food: Self::Food);
}

// 2. 为 Dog 实现这个 Trait
struct Dog;
struct Bone; // 狗吃骨头

impl Animal for Dog {
    type Food = Bone; // 明确指定 Dog 的 Food 是 Bone

    fn eat(&self, _food: Bone) {
        println!("狗正在啃骨头");
    }
}

// 3. 为 Cat 实现这个 Trait
struct Cat;
struct Fish; // 猫吃鱼

impl Animal for Cat {
    type Food = Fish; // 明确指定 Cat 的 Food 是 Fish

    fn eat(&self, _food: Fish) {
        println!("猫正在吃鱼");
    }
}

#[test]
fn main1() {
    // --- 重点在这里：使用完全限定语法来定义类型 ---

    // 语法：<具体类型 as 某个Trait>::关联类型名字

    // 如果我想定义一个变量，它的类型必须是“Dog 这种 Animal 对应的 Food”
    type DogFood = <Dog as Animal>::Food; // 实际上就是 Bone
    let my_bone: DogFood = Bone;

    // 如果我想定义一个变量，它的类型必须是“Cat 这种 Animal 对应的 Food”
    type CatFood = <Cat as Animal>::Food; // 实际上就是 Fish
    let my_fish: CatFood = Fish;

    // 调用
    Dog.eat(my_bone);
    Cat.eat(my_fish);
}

trait Engine {
    type Fuel; // 关联类型：燃料输入
    type Output; // 关联类型：能效输出

    // 核心方法：使用关联类型作为参数和返回值
    fn add_energy(&self, fuel: Self::Fuel) -> Self::Output;
}

struct GasEngine;
impl Engine for GasEngine {
    type Fuel = String; // 汽油引擎底层用 String
    type Output = u32; // 输出整数功率

    fn add_energy(&self, fuel: Self::Fuel) -> Self::Output {
        println!("正在往油箱注入: {}", fuel);
        100 // 返回功率
    }
}

struct ElectricEngine;
impl Engine for ElectricEngine {
    type Fuel = u64; // 电动引擎底层用 u64 (毫安时)
    type Output = f64; // 输出浮点数功率
    fn add_energy(&self, fuel: Self::Fuel) -> Self::Output {
        println!("正在充电: {} kWh", fuel);
        200.5
    }
}

// ==========================================
// 核心：泛型函数（这就像你的 Plonk Prover）
// ==========================================
// 这个函数不关心你是哪种引擎，它通过 E::Fuel 自动适配输入类型
fn operate_engine<E: Engine>(engine: &E, fuel: E::Fuel) -> E::Output {
    // 编译器会根据 E 的不同，自动确定 fuel 是 String 还是 u64
    let result = engine.add_energy(fuel);
    println!("引擎运转成功！");
    result
}

#[test]
fn main333() {
    let gas_eng = GasEngine;
    let ele_eng = ElectricEngine;

    // 1. 调用时，传入的是 String
    operate_engine(&gas_eng, String::from("95号汽油"));

    // 2. 调用时，传入的是 u64
    operate_engine(&ele_eng, 5000);

    // 3. 错误尝试：如果给电动引擎加汽油，编译器会直接报错
    // operate_engine(&ele_eng, String::from("汽油"));
    // 报错信息：expected `u64`, found `String`
}
