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

    case "multiLine":
      // 多线对比图表
      const multiLineSeries = [];
      if (data.series && Array.isArray(data.series)) {
        data.series.forEach((seriesData, index) => {
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
          data: data.xAxis || [],
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

      // 计算合理的坐标轴范围（排除极端值）
      const allX = points.map((p) => p.x).concat(centers.map((c) => c.x));
      const allY = points.map((p) => p.y).concat(centers.map((c) => c.y));

      // 使用四分位数方法过滤极端值
      const sortedX = [...allX].sort((a, b) => a - b);
      const sortedY = [...allY].sort((a, b) => a - b);

      const q1X = sortedX[Math.floor(sortedX.length * 0.25)];
      const q3X = sortedX[Math.floor(sortedX.length * 0.75)];
      const iqrX = q3X - q1X;
      const minX = Math.max(Math.min(...allX), q1X - 1.5 * iqrX);
      const maxX = Math.min(Math.max(...allX), q3X + 1.5 * iqrX);

      const q1Y = sortedY[Math.floor(sortedY.length * 0.25)];
      const q3Y = sortedY[Math.floor(sortedY.length * 0.75)];
      const iqrY = q3Y - q1Y;
      const minY = Math.max(Math.min(...allY), q1Y - 1.5 * iqrY);
      const maxY = Math.min(Math.max(...allY), q3Y + 1.5 * iqrY);

      // 按聚类分组数据
      const clusterGroups = {};
      points.forEach((point) => {
        const cluster = point.cluster;
        if (!clusterGroups[cluster]) {
          clusterGroups[cluster] = [];
        }
        clusterGroups[cluster].push([
          point.x,
          point.y,
          point.anomaly_score,
          point.cluster,
          point.zero_day_score,
          point.anomaly_score < 0.5 ? "异常" : "正常", // 异常标识
          point.zero_day_score > 0.5 ? "疑似零日攻击" : "常规告警", // 零日攻击标识
          point.alert_id || "N/A", // 告警ID
          point.is_confirmed_zero_day ? "已确认零日攻击" : "未确认", // 确认状态
        ]);
      });

      // 为每个聚类创建系列
      const scatterSeries = [];
      const clusterColors = [
        "#1f77b4",
        "#ff7f0e",
        "#2ca02c",
        "#d62728",
        "#9467bd",
        "#8c564b",
      ];

      Object.keys(clusterGroups).forEach((cluster, index) => {
        const clusterData = clusterGroups[cluster];
        const color = clusterColors[index % clusterColors.length];

        scatterSeries.push({
          name: `聚类 ${cluster}`,
          type: "scatter",
          symbolSize: function (data) {
            // 基于零日分数和异常分数调整气泡大小
            const zeroScore = data[4];
            const anomalyScore = Math.abs(data[2]);
            return Math.max(
              8,
              Math.min(25, zeroScore * 15 + anomalyScore * 10)
            );
          },
          itemStyle: {
            color: function (params) {
              const zeroScore = params.value[4];
              const anomalyScore = params.value[2];
              const isConfirmed = params.value[8] === "已确认零日攻击";

              // 已确认的零日攻击用深红色
              if (isConfirmed) {
                return "#d32f2f";
              }
              // 零日攻击用红色系（零日分数 > 0.5）
              else if (zeroScore > 0.5) {
                return "#ff4d4f";
              }
              // 异常但非零日攻击用橙色系（异常分数较低，表示异常）
              else if (anomalyScore < 0.5) {
                return "#fa8c16";
              }
              // 正常数据用绿色系（异常分数较高，表示正常）
              else {
                return "#52c41a";
              }
            },
            opacity: 0.8,
          },
          data: clusterData,
        });
      });

      // 添加聚类中心
      if (centers.length > 0) {
        const centersData = centers.map((center) => [center.x, center.y]);
        scatterSeries.push({
          name: "聚类中心",
          type: "scatter",
          symbolSize: 25, // 增加聚类中心的大小
          symbol: "diamond",
          itemStyle: {
            color: "#000",
            borderColor: "#fff",
            borderWidth: 3, // 增加边框宽度
          },
          emphasis: {
            itemStyle: {
              shadowBlur: 10,
              shadowColor: "#000",
              shadowOffsetX: 2,
              shadowOffsetY: 2,
            },
          },
          data: centersData,
          z: 10, // 确保聚类中心在最上层
        });
      }

      option = {
        title: {
          text: data.title || "AI告警数据聚类分析",
          subtext: "颜色表示威胁等级，大小表示异常程度",
          left: "center",
        },
        tooltip: {
          formatter: function (params) {
            if (params.seriesName === "聚类中心") {
              return `聚类中心<br/>坐标: (${params.value[0].toFixed(
                2
              )}, ${params.value[1].toFixed(2)})`;
            }

            const anomalyScore = params.value[2];
            const cluster = params.value[3];
            const zeroScore = params.value[4];
            const anomalyType = params.value[5];
            const threatType = params.value[6];
            const alertId = params.value[7];
            const confirmStatus = params.value[8];

            return `
              <div style="padding: 8px;">
                <div><strong>${threatType}</strong></div>
                <div>确认状态: <strong>${confirmStatus}</strong></div>
                <div>告警ID: ${alertId}</div>
                <div>聚类组: ${cluster}</div>
                <div>异常状态: ${anomalyType}</div>
                <div>异常分数: ${anomalyScore.toFixed(3)}</div>
                <div>零日分数: ${zeroScore.toFixed(3)}</div>
                <div>坐标: (${params.value[0].toFixed(
                  2
                )}, ${params.value[1].toFixed(2)})</div>
              </div>
            `;
          },
          backgroundColor: "rgba(50, 50, 50, 0.9)",
          borderColor: "#ccc",
          textStyle: {
            color: "#fff",
          },
        },
        legend: {
          data: scatterSeries.map((s) => s.name),
          top: "bottom",
          left: "center",
        },
        grid: {
          left: "10%",
          right: "10%",
          bottom: "15%",
          top: "15%",
          containLabel: true,
        },
        xAxis: {
          type: "value",
          name: "主成分1 (数据特征降维)",
          nameLocation: "middle",
          nameGap: 30,
          min: minX - (maxX - minX) * 0.1, // 添加10%的边距
          max: maxX + (maxX - minX) * 0.1,
          axisLine: {
            lineStyle: {
              color: "#666",
            },
          },
        },
        yAxis: {
          type: "value",
          name: "主成分2 (数据特征降维)",
          nameLocation: "middle",
          nameGap: 40,
          min: minY - (maxY - minY) * 0.1, // 添加10%的边距
          max: maxY + (maxY - minY) * 0.1,
          axisLine: {
            lineStyle: {
              color: "#666",
            },
          },
        },
        series: scatterSeries,
        // 添加数据缩放功能
        dataZoom: [
          {
            type: "inside",
            xAxisIndex: 0,
          },
          {
            type: "inside",
            yAxisIndex: 0,
          },
        ],
        // 添加工具箱
        toolbox: {
          feature: {
            dataZoom: {
              yAxisIndex: "none",
            },
            restore: {},
            saveAsImage: {},
          },
          right: 20,
          top: 20,
        },
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
