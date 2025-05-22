# AI 入侵检测系统

基于机器学习的网络入侵检测系统，能够自动识别和过滤日常低风险攻击警报，同时提供零日攻击检测和攻击进阶分析功能。

## 功能

- 数据库连接和数据提取
- 基线建立和学习
- 低风险攻击识别和分类
- 警报过滤和管理
- 零日攻击检测
- 攻击进阶分析和预测

## 使用方法

1. 安装依赖：`pip install -r requirements.txt`
2. 配置数据库连接：修改 `config/config.env` 文件
3. 训练基线模型：`python src/train_baseline.py`
4. 运行警报过滤：`python src/filter_alerts.py`
5. 进行高级检测：`python src/advanced_detection.py --zero-day --progression`

## 更新基线模型

每次执行`filter_alerts.py`后，系统会将低风险告警添加到基线数据库表`baseline_alerts`中。要利用这些新数据更新模型：

1. 重新训练包含基线数据的模型：`python src/train_baseline.py`
2. 如果仅想使用原始数据训练：`python src/train_baseline.py --no-baseline`

模型更新后，会自动覆盖原有模型文件：

- 预处理器：`models/preprocessor.joblib`
- 隔离森林模型：`models/baseline_isolation_forest.joblib`
- K 均值模型：`models/baseline_kmeans.joblib`

## 零日攻击检测

零日攻击检测功能使用增强的异常检测算法，能够识别出与已知模式不同的攻击行为：

```
python src/advanced_detection.py --zero-day --sensitivity 0.03
```

参数说明：

- `--zero-day`：启用零日攻击检测
- `--sensitivity`：检测敏感度，值越小越敏感(0.01-0.1)
- `--days`：分析最近几天的数据(默认 30 天)

## 攻击进阶分析

攻击进阶分析功能可以构建攻击路径图，识别攻击链，并预测攻击者的下一步行动：

```
python src/advanced_detection.py --progression --attacker 192.168.1.100
```

参数说明：

- `--progression`：启用攻击进阶分析
- `--attacker`：指定需要分析的攻击者 IP
- `--output-dir`：指定结果输出目录

## 项目结构

- `src/`: 源代码目录
- `data/`: 数据文件目录
- `models/`: 模型保存目录
- `config/`: 配置文件目录
