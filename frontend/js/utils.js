// 日期格式化函数
function formatDate(date, format = "YYYY-MM-DD HH:mm:ss") {
  if (!date) return "";

  const d = new Date(date);

  if (isNaN(d.getTime())) {
    return "";
  }

  const pad = (num) => String(num).padStart(2, "0");

  const replacements = {
    YYYY: d.getFullYear(),
    MM: pad(d.getMonth() + 1),
    DD: pad(d.getDate()),
    HH: pad(d.getHours()),
    mm: pad(d.getMinutes()),
    ss: pad(d.getSeconds()),
  };

  return format.replace(/YYYY|MM|DD|HH|mm|ss/g, (match) => replacements[match]);
}

// 通知消息显示函数
function showMessage(message, type = "info", duration = 3000) {
  // 检查是否已有消息容器
  let container = document.getElementById("message-container");

  if (!container) {
    container = document.createElement("div");
    container.id = "message-container";
    container.style.position = "fixed";
    container.style.top = "20px";
    container.style.right = "20px";
    container.style.zIndex = "9999";
    document.body.appendChild(container);
  }

  // 创建消息元素
  const messageEl = document.createElement("div");
  messageEl.className = `alert alert-${type}`;
  messageEl.style.marginBottom = "10px";
  messageEl.style.transition = "all 0.3s";
  messageEl.style.opacity = "0";
  messageEl.style.transform = "translateX(20px)";

  // 根据类型添加图标
  let icon = "";
  switch (type) {
    case "success":
      icon = "✓";
      break;
    case "error":
      icon = "✗";
      break;
    case "warning":
      icon = "⚠";
      break;
    default:
      icon = "ℹ";
  }

  messageEl.innerHTML = `<span class="alert-icon">${icon}</span> ${message}`;

  // 添加到容器
  container.appendChild(messageEl);

  // 动画显示
  setTimeout(() => {
    messageEl.style.opacity = "1";
    messageEl.style.transform = "translateX(0)";
  }, 10);

  // 定时移除
  setTimeout(() => {
    messageEl.style.opacity = "0";
    messageEl.style.transform = "translateX(20px)";

    setTimeout(() => {
      container.removeChild(messageEl);
    }, 300);
  }, duration);
}

// 加载中效果
function showLoading(container, text = "加载中...") {
  const el = document.querySelector(container);
  if (!el) return;

  el.innerHTML = `
    <div class="loading">
      <div class="loading-spinner"></div>
      <span>${text}</span>
    </div>
  `;
}

// 隐藏加载效果
function hideLoading(container) {
  const el = document.querySelector(container);
  if (!el) return;

  const loading = el.querySelector(".loading");
  if (loading) {
    loading.remove();
  }
}

// 初始化图表函数
function initChart(container, option, data = null) {
  const el = document.querySelector(container);
  if (!el) return null;

  // 确保有echarts
  if (!window.echarts) {
    console.error("echarts未加载");
    return null;
  }

  // 初始化图表
  const chart = echarts.init(el);

  // 如果提供了数据，则使用数据构建配置
  if (data) {
    option = buildChartOption(option, data);
  }

  chart.setOption(option);

  // 窗口大小变化时，调整图表大小
  window.addEventListener("resize", () => {
    chart.resize();
  });

  return chart;
}

// 根据数据类型构建图表配置
function buildChartOption(type, data) {
  let option = {};

  switch (type) {
    case "bar":
      option = {
        title: {
          text: data.title || "柱状图",
        },
        tooltip: {
          trigger: "axis",
        },
        xAxis: {
          type: "category",
          data: data.xAxis || [],
        },
        yAxis: {
          type: "value",
        },
        series: [
          {
            name: data.title || "数据",
            type: "bar",
            data: data.series || [],
            itemStyle: {
              color: "#3aa1ff",
            },
          },
        ],
      };
      break;

    case "pie":
      option = {
        title: {
          text: data.title || "饼图",
          left: "center",
        },
        tooltip: {
          trigger: "item",
          formatter: "{a} <br/>{b}: {c} ({d}%)",
        },
        legend: {
          orient: "vertical",
          left: "left",
          data: data.categories || [],
        },
        series: [
          {
            name: data.title || "数据",
            type: "pie",
            radius: "55%",
            center: ["50%", "60%"],
            data: data.series || [],
            emphasis: {
              itemStyle: {
                shadowBlur: 10,
                shadowOffsetX: 0,
                shadowColor: "rgba(0, 0, 0, 0.5)",
              },
            },
          },
        ],
      };
      break;

    case "line":
      option = {
        title: {
          text: data.title || "折线图",
        },
        tooltip: {
          trigger: "axis",
        },
        xAxis: {
          type: "category",
          data: data.xAxis || [],
          name: "类别",
        },
        yAxis: {
          type: "value",
          name: "数值",
        },
        series: [
          {
            name: data.title || "数据",
            type: "line",
            data: data.series || [],
            smooth: true,
            symbol: "circle",
            symbolSize: 8,
            lineStyle: {
              width: 3,
              color: "#ff5722",
            },
            itemStyle: {
              color: "#ff5722",
            },
            areaStyle: {
              color: {
                type: "linear",
                x: 0,
                y: 0,
                x2: 0,
                y2: 1,
                colorStops: [
                  {
                    offset: 0,
                    color: "rgba(255, 87, 34, 0.5)",
                  },
                  {
                    offset: 1,
                    color: "rgba(255, 87, 34, 0.1)",
                  },
                ],
              },
            },
          },
        ],
      };
      break;

    case "horizontalBar":
      option = {
        title: {
          text: data.title || "横向柱状图",
          left: "center",
        },
        tooltip: {
          trigger: "axis",
          axisPointer: {
            type: "shadow",
          },
        },
        grid: {
          left: "3%",
          right: "4%",
          bottom: "3%",
          containLabel: true,
        },
        xAxis: {
          type: "value",
          name: "数值",
        },
        yAxis: {
          type: "category",
          data: data.ips || [],
          name: "类别",
          axisLabel: {
            interval: 0,
            rotate: 0,
          },
        },
        series: [
          {
            name: data.title || "数据",
            type: "bar",
            data: data.counts || [],
            itemStyle: {
              color: function (params) {
                // 创建一个渐变色，数值越大颜色越深
                const colorList = ["#91cc75", "#fac858", "#ee6666"];
                const counts = data.counts || [];
                const max = Math.max(...counts);
                const ratio = params.value / max;
                if (ratio < 0.33) return colorList[0];
                else if (ratio < 0.66) return colorList[1];
                else return colorList[2];
              },
            },
            label: {
              show: true,
              position: "right",
              formatter: "{c}",
            },
          },
        ],
      };
      break;

    case "scatter":
      // 构建散点图配置
      const points = data.points || [];
      const centers = data.centers || [];

      // 转换点数据格式为ECharts所需的格式
      const scatterData = points.map((point) => [
        point.x,
        point.y,
        point.anomaly_score,
        point.cluster,
        point.zero_day_score,
      ]);

      // 转换聚类中心数据格式
      const centersData = centers.map((center) => [center.x, center.y]);

      option = {
        title: {
          text: data.title || "散点图",
        },
        tooltip: {
          formatter: function (params) {
            return (
              "异常分数: " +
              params.value[2].toFixed(3) +
              "<br/>" +
              "聚类: " +
              params.value[3] +
              "<br/>" +
              "零日分数: " +
              params.value[4].toFixed(3)
            );
          },
        },
        xAxis: {
          type: "value",
          name: "主成分1",
        },
        yAxis: {
          type: "value",
          name: "主成分2",
        },
        visualMap: {
          min: 0,
          max: 1,
          dimension: 2,
          inRange: {
            color: ["#52c41a", "#faad14", "#f5222d"],
          },
        },
        series: [
          {
            name: "告警数据",
            type: "scatter",
            symbolSize: function (data) {
              return Math.max(5, data[4] * 20); // 基于零日分数调整气泡大小
            },
            data: scatterData,
          },
          {
            name: "聚类中心",
            type: "scatter",
            symbolSize: 20,
            symbol: "diamond",
            itemStyle: {
              color: "#000",
            },
            data: centersData,
          },
        ],
      };
      break;

    default:
      console.error("未知的图表类型");
      break;
  }

  return option;
}

// 防抖函数
function debounce(fn, delay = 300) {
  let timer = null;

  return function (...args) {
    if (timer) clearTimeout(timer);

    timer = setTimeout(() => {
      fn.apply(this, args);
    }, delay);
  };
}

// 获取URL参数
function getUrlParam(name) {
  const urlParams = new URLSearchParams(window.location.search);
  return urlParams.get(name);
}

// 格式化数字
function formatNumber(num, digits = 0) {
  return Number(num).toLocaleString("zh-CN", {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  });
}

// 复制文本到剪贴板
function copyToClipboard(text) {
  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.style.position = "fixed";
  textarea.style.top = "-9999px";
  textarea.style.left = "-9999px";
  document.body.appendChild(textarea);
  textarea.select();

  try {
    document.execCommand("copy");
    showMessage("复制成功", "success");
  } catch (err) {
    showMessage("复制失败", "error");
  }

  document.body.removeChild(textarea);
}

// 获取状态标签
function getStatusTag(status) {
  switch (status) {
    case "success":
      return '<span class="tag tag-success">成功</span>';
    case "error":
      return '<span class="tag tag-error">错误</span>';
    case "warning":
      return '<span class="tag tag-warning">警告</span>';
    default:
      return '<span class="tag tag-primary">默认</span>';
  }
}

// 生成随机ID
function generateId(prefix = "") {
  return `${prefix}${Math.random().toString(36).substr(2, 9)}`;
}

// 导出工具函数
const utils = {
  formatDate,
  showMessage,
  showLoading,
  hideLoading,
  initChart,
  debounce,
  getUrlParam,
  formatNumber,
  copyToClipboard,
  getStatusTag,
  generateId,
};

// 供其他模块导入
window.utils = utils;
