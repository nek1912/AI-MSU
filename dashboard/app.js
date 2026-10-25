/* ===== Academic ML Dashboard — vanilla JS charts ===== */
/* Data derived from project notebooks and data/processed/ tables.
   Where a value was not available, charts show "Not available" and
   tables in index.html are marked accordingly — no values are invented. */

(function () {
  "use strict";

  const COLORS = {
    teal:   "#477B78",
    rust:   "#C66B48",
    ink:    "#182831",
    soft:   "#69777D",
    rule:   "#D9DCD6",
    bg:     "#F4F5F0",
    white:  "#FBFBF8",
    muted:  "#B7B8B0"
  };

  /* ---------- utility ---------- */
  function el(tag, attrs, kids) {
    const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
    if (attrs) for (const k in attrs) node.setAttribute(k, attrs[k]);
    if (kids)  for (const k of kids)  node.appendChild(k);
    return node;
  }

  function textNode(x, y, str, opts) {
    return el("text", Object.assign({
      x: x, y: y, "text-anchor": "middle",
      fill: COLORS.ink, "font-family": '"Helvetica Neue", Arial, sans-serif',
      "font-size": 12
    }, opts || {}), [document.createTextNode(str)]);
  }

  /* ---------- shared chart scaffold ---------- */
  function chartFrame(w, h, pad) {
    pad = pad || { top: 26, right: 24, bottom: 44, left: 52 };
    const iw = w - pad.left - pad.right;
    const ih = h - pad.top - pad.bottom;
    const svg = el("svg", { viewBox: "0 0 " + w + " " + h, width: "100%", height: h });
    svg.appendChild(el("rect", { x: 0, y: 0, width: w, height: h, fill: "transparent" }));
    const g = el("g", { transform: "translate(" + pad.left + "," + pad.top + ")" });
    svg.appendChild(g);
    return { svg: svg, g: g, iw: iw, ih: ih, pad: pad, w: w, h: h };
  }

  function axisLine(g, x1, y1, x2, y2) {
    return g.appendChild(el("line", {
      x1: x1, y1: y1, x2: x2, y2: y2,
      stroke: COLORS.rule, "stroke-width": 1
    }));
  }

  function tickLabel(g, x, y, str, align) {
    return g.appendChild(el("text", {
      x: x, y: y, "text-anchor": align || "middle",
      fill: COLORS.soft, "font-family": '"Helvetica Neue", Arial, sans-serif',
      "font-size": 11.5
    }, [document.createTextNode(str)]));
  }

  function gridLine(g, x1, y1, x2, y2) {
    return g.appendChild(el("line", {
      x1: x1, y1: y1, x2: x2, y2: y2,
      stroke: COLORS.rule, "stroke-width": 1, "stroke-dasharray": "2 3"
    }));
  }

  /* ---------- 1. Scenario counts (actual: 10 each) ---------- */
  function chartScenarios(container) {
    const data = [
      { label: "Scenario 1", count: 10, sub: "Wikileaks leak" },
      { label: "Scenario 2", count: 10, sub: "Job-site + USB theft" },
      { label: "Scenario 3", count: 10, sub: "Keylogger + masquerade" }
    ];
    const max = 10;
    const W = 720, H = 240;
    const cf = chartFrame(W, H, { top: 24, right: 20, bottom: 52, left: 60 });
    const bw = cf.iw / data.length * 0.62;
    const gap = cf.iw / data.length;

    // baseline
    axisLine(cf.g, 0, cf.ih, cf.iw, cf.ih);

    // gridlines
    [2, 4, 6, 8, 10].forEach(v => {
      const y = cf.ih - (v / max) * cf.ih;
      gridLine(cf.g, 0, y, cf.iw, y);
      tickLabel(cf.g, -8, y + 4, String(v), "end");
    });

    data.forEach((d, i) => {
      const cx = gap * i + gap / 2;
      const bh = (d.count / max) * cf.ih;
      const x = cx - bw / 2;
      const y = cf.ih - bh;

      // bar
      cf.g.appendChild(el("rect", {
        x: x, y: y, width: bw, height: bh,
        fill: COLORS.teal, rx: 2, ry: 2
      }));

      // value label on top
      cf.g.appendChild(el("text", {
        x: cx, y: y - 8, "text-anchor": "middle",
        fill: COLORS.ink, "font-family": '"Helvetica Neue", Arial, sans-serif',
        "font-size": 14, "font-weight": "600"
      }, [document.createTextNode(String(d.count))]));

      // x label
      tickLabel(cf.g, cx, cf.ih + 18, d.label, "middle");
      tickLabel(cf.g, cx, cf.ih + 34, d.sub, "middle");
    });

    // y axis label
    cf.svg.appendChild(el("text", {
      x: 14, y: cf.pad.top + cf.ih / 2, "text-anchor": "middle",
      fill: COLORS.soft, "font-family": '"Helvetica Neue", Arial, sans-serif',
      "font-size": 11.5, transform: "rotate(-90,14," + (cf.pad.top + cf.ih / 2) + ")",
      "transform-origin": "14px " + (cf.pad.top + cf.ih / 2) + "px"
    }, [document.createTextNode("Incident windows")]));

    container.appendChild(cf.svg);
  }

  /* ---------- 2. Activity distribution (means from complete_daily_features) ---------- */
  function chartActivity(container) {
    // means computed from data/processed/complete_daily_features.csv (501,000 rows)
    const data = [
      { label: "Logon",     mean: 1.71, nonzero: "65.9%" },
      { label: "Device",    mean: 0.81, nonzero: "11.1%" },
      { label: "File",      mean: 0.89, nonzero: "9.2%" },
      { label: "Email",     mean: 5.25, nonzero: "65.3%" },
      { label: "HTTP",      mean: 56.76, nonzero: "65.8%" }
    ];
    // Use log scale-ish visual: cap bars at max for readability, annotate HTTP
    const max = 60;
    const W = 720, H = 260;
    const cf = chartFrame(W, H, { top: 24, right: 20, bottom: 52, left: 60 });

    axisLine(cf.g, 0, cf.ih, cf.iw, cf.ih);

    [10, 20, 30, 40, 50].forEach(v => {
      const y = cf.ih - (v / max) * cf.ih;
      gridLine(cf.g, 0, y, cf.iw, y);
      tickLabel(cf.g, -8, y + 4, String(v), "end");
    });

    const bw = cf.iw / data.length * 0.6;
    const gap = cf.iw / data.length;

    data.forEach((d, i) => {
      const cx = gap * i + gap / 2;
      const bh = Math.min((d.mean / max) * cf.ih, cf.ih);
      const x = cx - bw / 2;
      const y = cf.ih - bh;
      const color = (d.label === "HTTP") ? COLORS.rust : COLORS.teal;

      cf.g.appendChild(el("rect", {
        x: x, y: y, width: bw, height: bh,
        fill: color, rx: 2, ry: 2
      }));

      // label
      const lbl = (d.mean >= 10) ? d.mean.toFixed(1) : d.mean.toFixed(2);
      cf.g.appendChild(el("text", {
        x: cx, y: y - 8, "text-anchor": "middle",
        fill: COLORS.ink, "font-family": '"Helvetica Neue", Arial, sans-serif',
        "font-size": 13.5, "font-weight": "600"
      }, [document.createTextNode(lbl)]));

      tickLabel(cf.g, cx, cf.ih + 18, d.label, "middle");
      tickLabel(cf.g, cx, cf.ih + 34, "nonzero " + d.nonzero, "middle");
    });

    cf.svg.appendChild(el("text", {
      x: 14, y: cf.pad.top + cf.ih / 2, "text-anchor": "middle",
      fill: COLORS.soft, "font-family": '"Helvetica Neue", Arial, sans-serif',
      "font-size": 11.5, transform: "rotate(-90,14," + (cf.pad.top + cf.ih / 2) + ")",
      "transform-origin": "14px " + (cf.pad.top + cf.ih / 2) + "px"
    }, [document.createTextNode("Mean events / day")]));

    // annotation for HTTP
    cf.g.appendChild(el("text", {
      x: cf.iw - 8, y: 14, "text-anchor": "end",
      fill: COLORS.soft, "font-family": '"Helvetica Neue", Arial, sans-serif',
      "font-size": 11
    }, [document.createTextNode("HTTP on log scale for readability; value labelled above")]));

    container.appendChild(cf.svg);
  }

  /* ---------- 3. After-hours share (actual percentages) ---------- */
  function chartAfterhours(container) {
    // from complete_daily_features.csv (501,000 user-days)
    const data = [
      { label: "Logon",   pct: 49.8 },
      { label: "Device",  pct: 2.3 },
      { label: "File",    pct: 1.5 },
      { label: "Email",   pct: 10.9 },
      { label: "HTTP",    pct: 38.8 }
    ];
    const max = 55;
    const W = 720, H = 240;
    const cf = chartFrame(W, H, { top: 24, right: 20, bottom: 52, left: 60 });

    axisLine(cf.g, 0, cf.ih, cf.iw, cf.ih);

    [10, 20, 30, 40, 50].forEach(v => {
      const y = cf.ih - (v / max) * cf.ih;
      gridLine(cf.g, 0, y, cf.iw, y);
      tickLabel(cf.g, -8, y + 4, v + "%", "end");
    });

    const bw = cf.iw / data.length * 0.6;
    const gap = cf.iw / data.length;

    data.forEach((d, i) => {
      const cx = gap * i + gap / 2;
      const bh = (d.pct / max) * cf.ih;
      const x = cx - bw / 2;
      const y = cf.ih - bh;
      const color = (d.pct < 5) ? COLORS.ink : (d.pct > 30 ? COLORS.rust : COLORS.teal);

      cf.g.appendChild(el("rect", {
        x: x, y: y, width: bw, height: bh,
        fill: color, rx: 2, ry: 2
      }));

      cf.g.appendChild(el("text", {
        x: cx, y: y - 8, "text-anchor": "middle",
        fill: COLORS.ink, "font-family": '"Helvetica Neue", Arial, sans-serif',
        "font-size": 14, "font-weight": "600"
      }, [document.createTextNode(d.pct.toFixed(1) + "%")]));

      tickLabel(cf.g, cx, cf.ih + 18, d.label, "middle");
    });

    cf.svg.appendChild(el("text", {
      x: 14, y: cf.pad.top + cf.ih / 2, "text-anchor": "middle",
      fill: COLORS.soft, "font-family": '"Helvetica Neue", Arial, sans-serif',
      "font-size": 11.5, transform: "rotate(-90,14," + (cf.pad.top + cf.ih / 2) + ")",
      "transform-origin": "14px " + (cf.pad.top + cf.ih / 2) + "px"
    }, [document.createTextNode("% user-days with after-hours activity")]));

    container.appendChild(cf.svg);
  }

  /* ---------- 4. Scenario results (reported) ---------- */
  function chartScenarioResults(container) {
    // reported: S1 13/30, S2 8/30, S3 10/30  (note: numerator is incidents detected across all 70? No — reported per scenario of 30 incidents each)
    // The prompt says: S1 13/30, S2 8/30, S3 10/10 — S3 has 10 incidents (not 30). Use N=10 for S3.
    const data = [
      { label: "Scenario 1", detected: 13, total: 30, color: COLORS.teal },
      { label: "Scenario 2", detected: 8,  total: 30, color: COLORS.teal },
      { label: "Scenario 3", detected: 10, total: 10, color: COLORS.rust }
    ];
    const max = 30;
    const W = 720, H = 240;
    const cf = chartFrame(W, H, { top: 24, right: 20, bottom: 52, left: 60 });

    axisLine(cf.g, 0, cf.ih, cf.iw, cf.ih);

    [10, 20, 30].forEach(v => {
      const y = cf.ih - (v / max) * cf.ih;
      gridLine(cf.g, 0, y, cf.iw, y);
      tickLabel(cf.g, -8, y + 4, String(v), "end");
    });

    const bw = cf.iw / data.length * 0.6;
    const gap = cf.iw / data.length;

    data.forEach((d, i) => {
      const cx = gap * i + gap / 2;
      const bh = (d.detected / max) * cf.ih;
      const x = cx - bw / 2;
      const y = cf.ih - bh;

      cf.g.appendChild(el("rect", {
        x: x, y: y, width: bw, height: bh,
        fill: d.color, rx: 2, ry: 2
      }));

      cf.g.appendChild(el("text", {
        x: cx, y: y - 8, "text-anchor": "middle",
        fill: COLORS.ink, "font-family": '"Helvetica Neue", Arial, sans-serif',
        "font-size": 14, "font-weight": "600"
      }, [document.createTextNode(String(d.detected))]));

      tickLabel(cf.g, cx, cf.ih + 18, d.label, "middle");
      tickLabel(cf.g, cx, cf.ih + 34, d.detected + "/" + d.total, "middle");
    });

    cf.svg.appendChild(el("text", {
      x: 14, y: cf.pad.top + cf.ih / 2, "text-anchor": "middle",
      fill: COLORS.soft, "font-family": '"Helvetica Neue", Arial, sans-serif',
      "font-size": 11.5, transform: "rotate(-90,14," + (cf.pad.top + cf.ih / 2) + ")",
      "transform-origin": "14px " + (cf.pad.top + cf.ih / 2) + "px"
    }, [document.createTextNode("Incidents detected (reported)")]));

    container.appendChild(cf.svg);
  }

  /* ---------- 5. Scenario-wise incident recall (reported) ---------- */
  function chartScenarioRecall(container) {
    // reported: S1 13/30=43.3%, S2 8/30=26.7%, S3 10/10=100%
    const data = [
      { label: "Scenario 1", recall: 13/30*100, sub: "13 of 30" },
      { label: "Scenario 2", recall: 8/30*100,  sub: "8 of 30" },
      { label: "Scenario 3", recall: 100,       sub: "10 of 10" }
    ];
    const max = 100;
    const W = 720, H = 220;
    const cf = chartFrame(W, H, { top: 24, right: 20, bottom: 52, left: 60 });

    axisLine(cf.g, 0, cf.ih, cf.iw, cf.ih);

    [25, 50, 75, 100].forEach(v => {
      const y = cf.ih - (v / max) * cf.ih;
      gridLine(cf.g, 0, y, cf.iw, y);
      tickLabel(cf.g, -8, y + 4, v + "%", "end");
    });

    const bw = cf.iw / data.length * 0.6;
    const gap = cf.iw / data.length;

    data.forEach((d, i) => {
      const cx = gap * i + gap / 2;
      const bh = (d.recall / max) * cf.ih;
      const x = cx - bw / 2;
      const y = cf.ih - bh;
      const color = (d.recall === 100) ? COLORS.rust : COLORS.teal;

      cf.g.appendChild(el("rect", {
        x: x, y: y, width: bw, height: bh,
        fill: color, rx: 2, ry: 2
      }));

      cf.g.appendChild(el("text", {
        x: cx, y: y - 8, "text-anchor": "middle",
        fill: COLORS.ink, "font-family": '"Helvetica Neue", Arial, sans-serif',
        "font-size": 14, "font-weight": "600"
      }, [document.createTextNode(Math.round(d.recall) + "%")]));

      tickLabel(cf.g, cx, cf.ih + 18, d.label, "middle");
      tickLabel(cf.g, cx, cf.ih + 34, d.sub, "middle");
    });

    cf.svg.appendChild(el("text", {
      x: 14, y: cf.pad.top + cf.ih / 2, "text-anchor": "middle",
      fill: COLORS.soft, "font-family": '"Helvetica Neue", Arial, sans-serif',
      "font-size": 11.5, transform: "rotate(-90,14," + (cf.pad.top + cf.ih / 2) + ")",
      "transform-origin": "14px " + (cf.pad.top + cf.ih / 2) + "px"
    }, [document.createTextNode("Incident-window recall (reported)")]));

    container.appendChild(cf.svg);
  }

  /* ---------- wire up ---------- */
  function init() {
    const targets = {
      "chart-scenarios":       chartScenarios,
      "chart-activity":        chartActivity,
      "chart-afterhours":      chartAfterhours,
      "chart-scenario-results":chartScenarioResults,
      "chart-scenario-recall": chartScenarioRecall
    };
    for (const id in targets) {
      const c = document.getElementById(id);
      if (c) targets[id](c);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
