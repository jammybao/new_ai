// 基础URL
const BASE_URL = "http://localhost:5000"; // 指向后端API服务地址

// 通用请求函数
async function request(url, options = {}) {
  try {
    const response = await fetch(`${BASE_URL}${url}`, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...options.headers,
      },
      mode: "cors",
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.message || "请求失败");
    }

    return data;
  } catch (error) {
    console.error("API请求错误:", error);
    throw error;
  }
}

// 系统健康检查API
async function checkHealth() {
  return request("/api/health");
}

// 系统版本信息API
async function getSystemVersions() {
  return request("/api/system/versions");
}

// 更新基线数据API
async function updateBaseline(params = {}) {
  return request("/api/baseline/update", {
    method: "POST",
    body: JSON.stringify(params),
  });
}

// 训练基线模型API
async function trainBaseline() {
  return request("/api/baseline/train", {
    method: "POST",
  });
}

// 零日攻击检测API
async function detectZeroDay(params = {}) {
  return request("/api/zeroday/detect", {
    method: "POST",
    body: JSON.stringify(params),
  });
}

// 获取零日攻击历史记录API
async function getZeroDayHistory(params = {}) {
  const queryParams = new URLSearchParams();

  if (params.page) queryParams.append("page", params.page);
  if (params.pageSize) queryParams.append("pageSize", params.pageSize);
  if (params.startDate) queryParams.append("startDate", params.startDate);
  if (params.endDate) queryParams.append("endDate", params.endDate);

  const query = queryParams.toString() ? `?${queryParams.toString()}` : "";

  return request(`/api/zeroday/history${query}`);
}

// 获取系统统计数据API
async function getStats() {
  return request("/api/stats");
}

// 获取各种图表数据API
async function getChartData(chartType, params = {}) {
  const queryParams = new URLSearchParams();

  if (params.days) queryParams.append("days", params.days);

  const query = queryParams.toString() ? `?${queryParams.toString()}` : "";

  return request(`/api/charts/${chartType}${query}`);
}

// 导出API函数
const api = {
  checkHealth,
  getSystemVersions,
  updateBaseline,
  trainBaseline,
  detectZeroDay,
  getZeroDayHistory,
  getStats,
  getChartData,
};

// 供其他模块导入
window.api = api;
