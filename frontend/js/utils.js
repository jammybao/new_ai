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
  if (loading && loading.parentNode) {
    try {
      loading.parentNode.removeChild(loading);
    } catch (e) {
      // 如果移除失败，尝试使用remove方法
      try {
        loading.remove();
      } catch (e2) {
        console.warn("无法移除加载元素:", e2);
      }
    }
  }
}

// 初始化图表函数
function initChart(container, option, data = null) {
  const el = document.querySelector(container);
  if (!el) {
    console.error(`图表容器未找到: ${container}`);
    return null;
  }

  // 确保有echarts
  if (!window.echarts) {
    console.error("echarts未加载");
    return null;
  }

  // 清理容器中可能存在的旧图表实例
  try {
    // 检查是否已有ECharts实例
    const existingChart = echarts.getInstanceByDom(el);
    if (existingChart) {
      existingChart.dispose();
    }

    // 清空容器内容，确保干净的环境
    el.innerHTML = "";
  } catch (e) {
    console.warn("清理图表容器时出现警告:", e);
  }

  // 初始化图表
  const chart = echarts.init(el);

  // 如果提供了数据，则使用数据构建配置
  if (data) {
    option = buildChartOption(option, data);
  }

  if (option) {
    chart.setOption(option);
  }

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
          data: data.xAxisData || [],
        },
        yAxis: {
          type: "value",
        },
        series: [
          {
            name:
              data.seriesData && data.seriesData[0]
                ? data.seriesData[0].name
                : "数据",
            type: "bar",
            data:
              data.seriesData && data.seriesData[0]
                ? data.seriesData[0].data
                : [],
            itemStyle: {
              color: "#3aa1ff",
            },
          },
        ],
      };
      break;

    case "pie":
      // 为威胁等级分布设置特定颜色
      let pieColors = ["#4ecdc4", "#ff9f43", "#ff6b6b", "#5865f2"]; // 默认颜色

      if (data.title && data.title.includes("威胁等级")) {
        // 威胁等级专用颜色映射
        const threatLevelColors = {
          高危: "#ff4757", // 红色
          中危: "#ffa502", // 橙色
          低危: "#2ed573", // 绿色
          未知: "#747d8c", // 灰色
        };

        // 为数据项设置对应颜色
        if (data.seriesData && Array.isArray(data.seriesData)) {
          data.seriesData.forEach((item) => {
            if (threatLevelColors[item.name]) {
              item.itemStyle = {
                color: threatLevelColors[item.name],
              };
            }
          });
        }
      }

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
          data: data.seriesData ? data.seriesData.map((item) => item.name) : [],
        },
        series: [
          {
            name: data.title || "数据",
            type: "pie",
            radius: "55%",
            center: ["50%", "60%"],
            data: data.seriesData || [],
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
          data: data.xAxisData || [],
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
            data:
              data.seriesData && data.seriesData[0]
                ? data.seriesData[0].data
                : [],
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

    case "heatmap":
      option = {
        title: {
          text: data.title || "热力图",
          left: "center",
        },
        tooltip: {
          position: "top",
          formatter: function (params) {
            const hour = data.xAxisData[params.data[0]];
            const day = data.yAxisData[params.data[1]];
            const count = params.data[2];
            return `${day} ${hour}<br/>异常告警: ${count} 次`;
          },
        },
        grid: {
          height: "50%",
          top: "15%",
        },
        xAxis: {
          type: "category",
          data: data.xAxisData || [],
          splitArea: {
            show: true,
          },
          axisLabel: {
            interval: 1, // 显示所有小时标签
            rotate: 45,
          },
        },
        yAxis: {
          type: "category",
          data: data.yAxisData || [],
          splitArea: {
            show: true,
          },
        },
        visualMap: {
          min: 0,
          max: data.maxCount || 100,
          calculable: true,
          orient: "horizontal",
          left: "center",
          bottom: "10%",
          inRange: {
            color: [
              "#313695",
              "#4575b4",
              "#74add1",
              "#abd9e9",
              "#e0f3f8",
              "#fee090",
              "#fdae61",
              "#f46d43",
              "#d73027",
              "#a50026",
            ],
          },
        },
        series: [
          {
            name: "异常告警数量",
            type: "heatmap",
            data: data.seriesData || [],
            label: {
              show: true,
              formatter: function (params) {
                return params.data[2] > 0 ? params.data[2] : "";
              },
            },
            emphasis: {
              itemStyle: {
                shadowBlur: 10,
                shadowColor: "rgba(0, 0, 0, 0.5)",
              },
            },
          },
        ],
      };
      break;

    case "multiLine":
      // 多线对比图表
      const multiLineSeries = [];
      if (data.seriesData && Array.isArray(data.seriesData)) {
        data.seriesData.forEach((seriesData, index) => {
          // 根据数据名称设置对应颜色
          let color = "#4ecdc4"; // 默认青绿色
          if (
            seriesData.name.includes("总告警") ||
            seriesData.name.includes("总数")
          ) {
            color = "#4ecdc4"; // 青绿色 - 总告警量
          } else if (
            seriesData.name.includes("异常告警") ||
            seriesData.name.includes("异常")
          ) {
            color = "#fdcb6e"; // 黄色 - 异常告警数量
          } else if (
            seriesData.name.includes("零日告警") ||
            seriesData.name.includes("零日")
          ) {
            color = "#ff6b6b"; // 红色 - 零日告警数量
          }

          multiLineSeries.push({
            name: seriesData.name || `数据${index + 1}`,
            type: "line",
            data: seriesData.data || [],
            smooth: true,
            symbol: "circle",
            symbolSize: 6,
            lineStyle: {
              width: 3,
              color: seriesData.color || color,
            },
            itemStyle: {
              color: seriesData.color || color,
            },
          });
        });
      }

      option = {
        title: {
          text: data.title || "多线对比图",
          left: "center",
        },
        tooltip: {
          trigger: "axis",
          axisPointer: {
            type: "cross",
            label: {
              backgroundColor: "#6a7985",
            },
          },
        },
        legend: {
          data: multiLineSeries.map((s) => s.name),
          top: "10%",
          left: "center",
        },
        grid: {
          left: "3%",
          right: "4%",
          bottom: "15%",
          top: "20%",
          containLabel: true,
        },
        xAxis: {
          type: "category",
          data: data.xAxisData || [],
          name: "日期",
          nameLocation: "middle",
          nameGap: 25,
          axisLabel: {
            rotate: 45,
            formatter: function (value) {
              // 简化日期显示
              return value.slice(5); // 显示月-日
            },
          },
        },
        yAxis: {
          type: "value",
          name: "数量",
          nameLocation: "middle",
          nameGap: 40,
          min: 0,
        },
        series: multiLineSeries,
        dataZoom: [
          {
            type: "inside",
            start: 0,
            end: 100,
          },
          {
            show: true,
            type: "slider",
            top: "95%",
            start: 0,
            end: 100,
            height: 20,
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
          data: data.yAxisData || [],
          name: "类别",
          axisLabel: {
            interval: 0,
            rotate: 0,
          },
        },
        series: [
          {
            name:
              data.seriesData && data.seriesData[0]
                ? data.seriesData[0].name
                : "数据",
            type: "bar",
            data:
              data.seriesData && data.seriesData[0]
                ? data.seriesData[0].data
                : [],
            itemStyle: {
              color: function (params) {
                // 创建一个渐变色，数值越大颜色越深
                const colorList = ["#91cc75", "#fac858", "#ee6666"];
                const counts =
                  data.seriesData && data.seriesData[0]
                    ? data.seriesData[0].data
                    : [];
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
