# AI-IDS API 接口文档

本文档详细描述了 AI-IDS 系统提供的 API 接口，供前端开发人员参考。

## 基础信息

- **基础 URL**: `http://服务器IP:5000`
- **数据格式**: 所有请求和响应均使用 JSON 格式
- **认证方式**: 暂无认证，建议在生产环境中添加

## 通用响应格式

所有 API 响应均包含以下字段：

```json
{
  "status": "success|error|warning",  // 响应状态
  "message": "状态描述信息",           // 可选，状态描述
  "data|error": { ... }              // 响应数据或错误信息
}
```

## 接口详情

### 1. 健康检查

检查 API 服务运行状态。

- **URL**: `/api/health`
- **方法**: `GET`
- **参数**: 无

**成功响应示例**:

```json
{
  "status": "ok",
  "time": "2023-05-22 15:30:45",
  "models_loaded": true,
  "last_model_load": "2023-05-22 12:00:00"
}
```

### 2. 基线数据更新

更新系统基线数据。

- **URL**: `/api/baseline/update`
- **方法**: `POST`
- **请求体**:

```json
{
  "days": 30, // 可选，从多少天前开始收集数据
  "min_score": 0.5, // 可选，阈值分数，低于此分数的告警被视为正常
  "exclude_categories": ["严重漏洞", "勒索软件", "数据泄露"] // 可选，要排除的告警类别
}
```

**成功响应示例**:

```json
{
  "status": "success",
  "message": "基线数据更新完成，添加了 150 条记录",
  "added_count": 150,
  "update_time": "2023-05-22 15:30:45"
}
```

### 3. 基线模型训练

训练基线模型和零日检测器。

- **URL**: `/api/baseline/train`
- **方法**: `POST`
- **请求体**: 无

**成功响应示例**:

```json
{
  "status": "success",
  "message": "基线模型训练完成",
  "models_loaded": true,
  "update_time": "2023-05-22 15:45:30"
}
```

### 4. 零日攻击检测

执行零日攻击检测。

- **URL**: `/api/zeroday/detect`
- **方法**: `POST`
- **请求体**:

```json
{
  "hours": 24 // 可选，检测最近多少小时的数据
}
```

**成功响应示例**:

```json
{
  "status": "success",
  "message": "检测完成: 发现 25 个异常，其中 3 个可能是零日攻击",
  "total_alerts": 100,
  "anomaly_count": 25,
  "zero_day_count": 3,
  "saved_count": 3,
  "zero_day_details": [
    {
      "id": 12345,
      "event_time": "2023-05-22 13:45:30",
      "category": "攻击探测",
      "src_ip": "192.168.1.100",
      "dst_ip": "10.0.0.5",
      "zero_day_score": 0.85,
      "signature": "未知攻击模式"
    }
    // ...更多记录
  ]
}
```

**警告响应示例** (数据不足):

```json
{
  "status": "warning",
  "message": "告警数据不足，无法进行检测，当前只有 5 条告警",
  "count": 5
}
```

### 5. 零日攻击历史查询

查询历史零日攻击记录。

- **URL**: `/api/zeroday/history`
- **方法**: `GET`
- **参数**:
  - `page`: 页码，默认 1
  - `pageSize`: 每页记录数，默认 10
  - `startDate`: 开始日期，格式 YYYY-MM-DD，可选
  - `endDate`: 结束日期，格式 YYYY-MM-DD，可选

**成功响应示例**:

```json
{
  "status": "success",
  "data": [
    {
      "id": 12345,
      "event_time": "2023-05-22 13:45:30",
      "detected_at": "2023-05-22 14:00:00",
      "category": "攻击探测",
      "src_ip": "192.168.1.100",
      "dst_ip": "10.0.0.5",
      "threat_level": 3,
      "zero_day_score": 0.85,
      "signature": "未知攻击模式"
    }
    // ...更多记录
  ],
  "total": 56,
  "page": 1,
  "page_size": 10
}
```

### 6. 系统统计数据

获取系统统计数据。

- **URL**: `/api/stats`
- **方法**: `GET`
- **参数**: 无

**成功响应示例**:

```json
{
  "status": "success",
  "baseline_count": 1200,
  "zeroday_count": 45,
  "daily_alerts": [
    { "date": "2023-05-01", "count": 12 },
    { "date": "2023-05-02", "count": 15 }
    // ...更多日期
  ],
  "categories": [
    { "category": "攻击探测", "count": 20 },
    { "category": "漏洞利用", "count": 15 }
    // ...更多分类
  ],
  "top_source_ips": [
    { "ip": "192.168.1.100", "count": 10 },
    { "ip": "10.0.0.5", "count": 8 }
    // ...更多IP
  ],
  "monthly_trend": [
    { "month": "2023-01", "count": 5 },
    { "month": "2023-02", "count": 8 }
    // ...更多月份
  ]
}
```

### 7. 图表数据

获取各类图表数据。

- **URL**: `/api/charts/<chart_type>`
- **方法**: `GET`
- **chart_type**:
  - `daily_alerts`: 每日告警统计
  - `category_distribution`: 零日攻击分类分布
  - `monthly_trend`: 每月零日攻击趋势

**成功响应示例**:

```json
{
  "status": "success",
  "image": "base64编码的图像数据..." // 可直接在<img>标签的src属性中使用: src="data:image/png;base64,图像数据"
}
```

### 8. 系统版本信息

获取系统各组件的版本和更新时间信息。

- **URL**: `/api/system/versions`
- **方法**: `GET`
- **参数**: 无

**成功响应示例**:

```json
{
  "status": "success",
  "versions": {
    "baseline_data": {
      "last_update": "2023-05-22 15:30:45",
      "count": 1200
    },
    "baseline_model": {
      "last_update": "2023-05-22 15:45:30"
    },
    "zero_day_model": {
      "last_update": "2023-05-22 15:45:30"
    },
    "last_detection": {
      "last_update": "2023-05-22 16:00:00",
      "count": 45
    }
  },
  "model_files": {
    "preprocessor.joblib": {
      "size": 12345678,
      "modified": "2023-05-22 15:45:30"
    },
    "baseline_isolation_forest.joblib": {
      "size": 8765432,
      "modified": "2023-05-22 15:45:30"
    },
    "baseline_kmeans.joblib": {
      "size": 5678901,
      "modified": "2023-05-22 15:45:30"
    },
    "zero_day_detector.joblib": {
      "size": 23456789,
      "modified": "2023-05-22 15:45:30"
    }
  },
  "system_time": "2023-05-22 16:30:00"
}
```

## 错误处理

所有 API 在遇到错误时都会返回统一格式的错误响应：

```json
{
  "status": "error",
  "message": "错误详情描述"
}
```

常见 HTTP 状态码：

- `200`: 请求成功
- `400`: 请求参数错误
- `404`: 资源不存在
- `500`: 服务器内部错误

## 前端实现建议

根据这些 API 接口，我们建议前端实现以下几个页面：

### 1. 控制面板 (Dashboard)

- 显示系统状态、基线数据量和零日攻击数量
- 展示最近检测到的零日攻击
- 使用图表显示每日告警趋势和攻击分类分布

### 2. 基线管理页面

- 提供手动更新基线数据的表单，可设置时间范围
- 提供训练模型的按钮
- 显示基线数据的统计信息和历史更新记录

### 3. 零日检测页面

- 提供手动执行零日检测的表单，可设置时间范围
- 显示检测结果，包括异常数量和零日攻击数量
- 列出检测到的零日攻击详细信息

### 4. 历史记录页面

- 提供时间范围筛选和分页查询功能
- 列表显示历史零日攻击记录
- 提供详细查看单条记录的功能

### 5. 数据可视化页面

- 展示各类统计图表，如每日告警统计、攻击分类分布和月度趋势
- 提供图表交互功能，如时间范围选择和数据钻取

## 实现示例

以下是一个使用 Vue.js 实现零日检测页面的简单示例：

```html
<template>
  <div class="zeroday-detection">
    <h1>零日攻击检测</h1>

    <div class="detection-form">
      <div class="form-group">
        <label for="hours">检测时间范围（小时）</label>
        <input id="hours" v-model="hours" type="number" min="1" max="72" />
      </div>
      <button @click="detectZeroDay" :disabled="isLoading">
        {{ isLoading ? '检测中...' : '开始检测' }}
      </button>
    </div>

    <div v-if="result" class="detection-result">
      <div class="result-summary">
        <h2>检测结果</h2>
        <p>{{ result.message }}</p>
        <div class="stats">
          <div class="stat-item">
            <span class="label">总告警数</span>
            <span class="value">{{ result.total_alerts }}</span>
          </div>
          <div class="stat-item">
            <span class="label">异常数</span>
            <span class="value">{{ result.anomaly_count }}</span>
          </div>
          <div class="stat-item">
            <span class="label">零日攻击</span>
            <span class="value">{{ result.zero_day_count }}</span>
          </div>
        </div>
      </div>

      <div
        v-if="result.zero_day_details && result.zero_day_details.length > 0"
        class="details"
      >
        <h3>零日攻击详情</h3>
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>时间</th>
              <th>分类</th>
              <th>来源IP</th>
              <th>目标IP</th>
              <th>异常分数</th>
              <th>特征</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="item in result.zero_day_details" :key="item.id">
              <td>{{ item.id }}</td>
              <td>{{ item.event_time }}</td>
              <td>{{ item.category }}</td>
              <td>{{ item.src_ip }}</td>
              <td>{{ item.dst_ip }}</td>
              <td>{{ item.zero_day_score.toFixed(2) }}</td>
              <td>{{ item.signature }}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div v-else-if="result.zero_day_count === 0" class="no-data">
        <p>未检测到零日攻击</p>
      </div>
    </div>

    <div v-if="error" class="error-message">
      <p>{{ error }}</p>
    </div>
  </div>
</template>

<script>
  export default {
    data() {
      return {
        hours: 24,
        isLoading: false,
        result: null,
        error: null,
      };
    },
    methods: {
      async detectZeroDay() {
        this.isLoading = true;
        this.error = null;
        this.result = null;

        try {
          const response = await fetch("/api/zeroday/detect", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
            },
            body: JSON.stringify({ hours: this.hours }),
          });

          const data = await response.json();

          if (data.status === "success" || data.status === "warning") {
            this.result = data;
          } else {
            this.error = data.message || "检测失败";
          }
        } catch (e) {
          this.error = "请求失败: " + e.message;
        } finally {
          this.isLoading = false;
        }
      },
    },
  };
</script>
```
