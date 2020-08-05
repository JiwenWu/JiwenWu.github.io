---
title: Redis学习与应用-位图
date: 2019-08-20 14:11:03
tags: Redis
Articles: 技术
---

## 什么是位图

> 位图`bitmap`是通过一个`bit`来表示某个元素对应的值或者状态，是由一组bit位组成，每个bit位对应0和1两个状态，虽然内部还是采用string类型进行存储，但是redis提供了直接操作位图的指令，可以把他看作是一个bit数组，数组的下标就是偏移量。

<!-- more -->

## 常用命令介绍

### 一、SETBIT key offset value
> 可用版本：>=2.20
> 时间复杂度：O(1)

#### 作用
对 `key` 所储存的字符串值，设置或清除指定偏移量上的位(bit)。
位的设置或清除取决于 `value` 参数，可以是 `0` 也可以是 `1` 。
当 `key` 不存在时，自动生成一个新的字符串值。
字符串会进行伸展(grown)以确保它可以将 `value` 保存在指定的偏移量上。当字符串值进行伸展时，空白位置以 `0` 填充。
`offset` 参数必须大于或等于 `0` ，小于 2^32 (bit 映射被限制在 512 MB 之内)。


#### 返回值

原来储存的位

#### 示例

```shell
# 在key值为bitkey的偏移量0处,设置值为1
redis> setbit bitkey 0 1
# 返回原存储的值
(integer) 0
# 在key值为bitkey的偏移量0处,设置值为1
redis> setbit bitkey 0 0
# 返回原存储的值
(integer) 1
```

### 二、GETBIT key offset

> 可用版本：>=2.2.0
>
> 时间复杂度：O(1)

#### 作用

对` key` 所储存的字符串值，获取指定偏移量上的位(bit)。
当 `offset` 比字符串值的长度大，或者 `key` 不存在时，返回 `0` 。

#### 返回值
字符串值指定偏移量上的位

#### 示例
```shell
# 不存在的key
redis>getbit bitkey_0
(integer) 0
reids>setbit bitkey_0 0 0
(integer) 1
# 超过默认的偏移量（没有grown）
redis>getbit bitkey_0 10000
(integer) 0
redis>getbit bitkey_0 0
(integer) 1
```

### 三、 BITCOUNT key [start] [end]

> 可用版本：>=2.6.0
>
> 时间复杂度：O(N)

#### 作用

计算给定字符串中，被设置为 1 的比特位的数量。
一般情况下，给定的整个字符串都会被进行计数，通过指定额外的 start 或 end 参数，可以让计数只在特定的位上进行。
start 和 end 参数的设置和 GETRANGE key start end 命令类似，都可以使用负数值： 比如 -1 表示最后一个字节， -2 表示倒数第二个字节，以此类推。
不存在的 key 被当成是空字符串来处理，因此对一个不存在的 key 进行 BITCOUNT 操作，结果为 0 。
#### 示例
```shell
redis>setbit key_count 0 1
(integer) 0
redis>setbit key_count 1 1
(integer) 0
redis>setbit key_count 2 0
(integer) 0
redis>bitcount key_count
(integer) 2
```
### 四、BITPOS key bit [start] [end]
> 可用版本：>= 2.8.7
> 时间复杂度：O(N)，其中N为位图包含的二进制位数量


#### 作用
返回位图中第一个值为bit的二进制的位置
在默认情况下，命令将检测整个位图，但用户也可以通过start和end参数来指定要检测的范围
#### 返回值
整数返回
#### 示例
```shell
redis>setbit key_pos 2 1
(integer) 0
redis>bitpos key_pos 0
(integer) 0
redis>bitpos key_pos 1
(integer) 2
```

### 五、BITOP operation destkey key [key …]

> 可用版本：>=2.6.0
>
> 时间复杂度：O(N)

#### 作用

对一个或多个保存二进制位的字符串 `key` 进行位元操作，并将结果保存到 `destkey` 上。
`operation` 可以是 `AND` 、 `OR` 、 `NOT` 、 `XOR` 这四种操作中的任意一种：
- `BITOP AND destkey key [key ...]` ，对一个或多个 `key` 求逻辑并，并将结果保存到 `destkey` 。
- `BITOP OR destkey key [key ...]` ，对一个或多个 `key` 求逻辑或，并将结果保存到 `destkey` 。
- `BITOP XOR destkey key [key ...]` ，对一个或多个 `key` 求逻辑异或，并将结果保存到 `destkey` 。
- `BITOP NOT destkey key` ，对给定 `key` 求逻辑非，并将结果保存到 `destkey` 。
除了 `NOT` 操作之外，其他操作都可以接受一个或多个 `key` 作为输入。

#### 返回值

保存到 `destkey` 的字符串的长度，和输入 `key` 中最长的字符串长度相等。

#### 示例

```shell
# 先保存几组
# key_1:1001  key_2:1011 
redis> setbit key_1 0 1
(integer) 0
redis> setbit key_1 3 1
(integer) 0
redis> setbit key_2 0 1
(integer) 0
reids> setbit key_2 2 1
(integer) 0
reids> setbit key_2 3 1
(integer) 0
# AND key求逻辑并
redis> bitop and key_and key_1 key_2 # 结果将是1001
(integer) 1
# OR key求逻辑或
redis> bitop or key_or key_1 key_2 # 1011
(integer) 1
# XOR key求逻辑异或
redis> bitop xor key_xor key_1 key_2 # 0100
(integer) 1
# NOT key求逻辑非
redis> bitop not key_not key_1 # 0110
(integer) 1
```

### 六、BITFIELD key [GET type offset] [SET type offset value] [INCRBY type offset increment] [OVERFLOW WRAP|SAT|FAIL]

> 可用版本：>= 3.2.0
>
> 时间复杂度：每个子命令的复杂度为 O(1) 

#### 作用

一次对多个位范围进行操作。bitfield 有三个子指令，分别是 get/set/incrby。每个指令都可以对指定片段做操作。

#### 返回值

返回一个数组作为回复， 数组中的每个元素就是对应操作的执行结果。

#### 案例

```shell
# 从第1位开始取4位，设值为5（有符号数）
redis> BITFIELD key SET i4 0 5
1) (integer) 0

# 从第1位开始取4位，结果为有符号数
redis> BITFIELD key GET i4 0
1) (integer) 5

# 从第1位取4位，结果为有符号数
# 从第5位取4位，设值为6，结果为无符号数
# 从第5位去4位，值增加1，结果为无符号数
redis> BITFIELD key GET i4 0 SET u4 4 6 INCRBY u4 4 1
1) (integer) 5
2) (integer) 0
3) (integer) 7
```

BITFIELD还提供了三种溢出策略：

- `WRAP`（wrap around，回绕）。一个i8的整数，值为127，递增1会导致值变为-128；
- `SAT`（saturation arithmetic，饱和计算）。一个i8的整数，值为120，递增10结果变为127（i8 类型所能储存的最大整数值）；
- `FAIL`。  发生溢出时，操作失败。并返回空值表示计算未被执行。

```rust
redis> BITFIELD tian_key SET i8 0 127 OVERFLOW WRAP INCRBY i8 0 1
1) (integer) 0
2) (integer) -128
redis> BITFIELD tian_key_2 SET i8 0 120 OVERFLOW SAT INCRBY i8 0 10
1) (integer) 0
2) (integer) 127
redis> BITFIELD tian_key_3 SET i8 0 127 OVERFLOW FAIL INCRBY i8 0 1
1) (integer) 0
2) (nil)
```

