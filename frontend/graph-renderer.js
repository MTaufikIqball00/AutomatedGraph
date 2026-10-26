/**
 * Interactive SVG Knowledge Graph Explorer Renderer
 * Supports zoom, pan, directional arrowheads, optional edge labels, keyboard navigation,
 * and active node/edge selection highlighting.
 */
import { ENTITY_PALETTE } from "./ui-components.js";

const SVG_NS = "http://www.w3.org/2000/svg";

export class InteractiveGraphRenderer {
  constructor(svgElement, { onSelectNode, onSelectEdge }) {
    this.svg = svgElement;
    this.onSelectNode = onSelectNode;
    this.onSelectEdge = onSelectEdge;

    this.nodes = [];
    this.edges = [];
    this.selectedNodeId = null;
    this.selectedEdgeId = null;
    this.showEdgeLabels = false;

    // Viewport transform state
    this.scale = 1;
    this.translateX = 0;
    this.translateY = 0;
    this.isDragging = false;
    this.dragStartX = 0;
    this.dragStartY = 0;

    this.viewportGroup = null;
    this._bindViewportEvents();
  }

  _bindViewportEvents() {
    this.svg.addEventListener("mousedown", (e) => {
      if (e.target !== this.svg && e.target.tagName !== "rect") return;
      this.isDragging = true;
      this.dragStartX = e.clientX - this.translateX;
      this.dragStartY = e.clientY - this.translateY;
      this.svg.classList.add("cursor-grabbing");
    });

    window.addEventListener("mousemove", (e) => {
      if (!this.isDragging) return;
      this.translateX = e.clientX - this.dragStartX;
      this.translateY = e.clientY - this.dragStartY;
      this._applyTransform();
    });

    window.addEventListener("mouseup", () => {
      if (this.isDragging) {
        this.isDragging = false;
        this.svg.classList.remove("cursor-grabbing");
      }
    });

    this.svg.addEventListener(
      "wheel",
      (e) => {
        e.preventDefault();
        const factor = e.deltaY < 0 ? 1.12 : 0.89;
        this.zoomBy(factor);
      },
      { passive: false }
    );
  }

  zoomBy(factor) {
    this.scale = Math.min(2.6, Math.max(0.45, this.scale * factor));
    this._applyTransform();
  }

  resetViewport() {
    this.scale = 1;
    this.translateX = 0;
    this.translateY = 0;
    this._applyTransform();
  }

  setShowEdgeLabels(flag) {
    this.showEdgeLabels = Boolean(flag);
    this.render(this.nodes, this.edges);
  }

  _applyTransform() {
    if (this.viewportGroup) {
      this.viewportGroup.setAttribute(
        "transform",
        `translate(${this.translateX}, ${this.translateY}) scale(${this.scale})`
      );
    }
  }

  render(nodes = [], edges = []) {
    this.nodes = nodes;
    this.edges = edges;
    this.svg.innerHTML = "";

    const width = 880;
    const height = 540;

    if (!nodes.length) {
      const emptyText = document.createElementNS(SVG_NS, "text");
      emptyText.setAttribute("x", String(width / 2));
      emptyText.setAttribute("y", String(height / 2));
      emptyText.setAttribute("text-anchor", "middle");
      emptyText.setAttribute("fill", "#64748b");
      emptyText.setAttribute("font-size", "13");
      emptyText.textContent =
        "No graph entities match the active filter in this tenant scope.";
      this.svg.appendChild(emptyText);
      return;
    }

    // 1. Define directional arrow markers for explicit and inferred edges
    const defs = document.createElementNS(SVG_NS, "defs");
    defs.innerHTML = `
      <marker id="arrow-explicit" viewBox="0 0 10 10" refX="21" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
        <path d="M 0 1.5 L 10 5 L 0 8.5 z" fill="#64748b"></path>
      </marker>
      <marker id="arrow-inferred" viewBox="0 0 10 10" refX="21" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
        <path d="M 0 1.5 L 10 5 L 0 8.5 z" fill="#a855f7"></path>
      </marker>
      <marker id="arrow-active" viewBox="0 0 10 10" refX="21" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse">
        <path d="M 0 1.5 L 10 5 L 0 8.5 z" fill="#3b82f6"></path>
      </marker>
    `;
    this.svg.appendChild(defs);

    const viewport = document.createElementNS(SVG_NS, "g");
    this.viewportGroup = viewport;
    this._applyTransform();
    this.svg.appendChild(viewport);

    // 2. Compute concentric hub-and-ring layout sorted by degree & community
    const cx = width / 2;
    const cy = height / 2;
    const posMap = {};
    const total = nodes.length;

    nodes.forEach((node, idx) => {
      let ringRatio = 0.88;
      if (idx === 0 && total > 4) {
        posMap[node.entity_id] = { x: cx, y: cy, node };
        return;
      }
      if (idx < 9) ringRatio = 0.38;
      else if (idx < 24) ringRatio = 0.66;

      const ringItems = idx < 9 ? Math.min(8, total - 1) : idx < 24 ? Math.min(15, total - 9) : Math.max(1, total - 24);
      const localIdx = idx < 9 ? idx - 1 : idx < 24 ? idx - 9 : idx - 24;
      const angleOffset = idx < 9 ? 0 : idx < 24 ? 0.25 : 0.5;
      const angle = angleOffset + (2 * Math.PI * localIdx) / Math.max(1, ringItems);

      const rx = (width / 2 - 75) * ringRatio;
      const ry = (height / 2 - 58) * ringRatio;
      posMap[node.entity_id] = {
        x: Math.round(cx + rx * Math.cos(angle)),
        y: Math.round(cy + ry * Math.sin(angle)),
        node,
      };
    });

    // Identify 1-hop neighbors of currently selected node for visual emphasis
    const neighborIds = new Set();
    if (this.selectedNodeId) {
      neighborIds.add(this.selectedNodeId);
      edges.forEach((e) => {
        if (e.source_id === this.selectedNodeId) neighborIds.add(e.target_id);
        if (e.target_id === this.selectedNodeId) neighborIds.add(e.source_id);
      });
    }

    // 3. Render Edges
    edges.forEach((edge) => {
      const src = posMap[edge.source_id];
      const tgt = posMap[edge.target_id];
      if (!src || !tgt) return;

      const isEdgeSelected = this.selectedEdgeId === edge.edge_id;
      const isConnectedToSelectedNode =
        this.selectedNodeId &&
        (edge.source_id === this.selectedNodeId || edge.target_id === this.selectedNodeId);
      const isDimmed =
        (this.selectedNodeId && !isConnectedToSelectedNode) ||
        (this.selectedEdgeId && !isEdgeSelected);

      const edgeGroup = document.createElementNS(SVG_NS, "g");
      edgeGroup.setAttribute("class", "cursor-pointer");
      edgeGroup.setAttribute("tabindex", "0");
      edgeGroup.setAttribute("role", "button");
      edgeGroup.setAttribute(
        "aria-label",
        `Relationship ${edge.source_name} ${edge.relationship_type} ${edge.target_name}`
      );

      const line = document.createElementNS(SVG_NS, "line");
      line.setAttribute("x1", String(src.x));
      line.setAttribute("y1", String(src.y));
      line.setAttribute("x2", String(tgt.x));
      line.setAttribute("y2", String(tgt.y));

      const strokeColor =
        isEdgeSelected || isConnectedToSelectedNode
          ? "#3b82f6"
          : edge.is_inferred
          ? "#a855f7"
          : "#64748b";
      line.setAttribute("stroke", strokeColor);
      line.setAttribute(
        "stroke-width",
        isEdgeSelected || isConnectedToSelectedNode ? "2.8" : edge.is_inferred ? "1.6" : "2.0"
      );
      line.setAttribute("stroke-opacity", isDimmed ? "0.22" : "0.85");
      if (edge.is_inferred) {
        line.setAttribute("stroke-dasharray", "5,4");
      }
      line.setAttribute(
        "marker-end",
        isEdgeSelected || isConnectedToSelectedNode
          ? "url(#arrow-active)"
          : edge.is_inferred
          ? "url(#arrow-inferred)"
          : "url(#arrow-explicit)"
      );

      edgeGroup.appendChild(line);

      if (this.showEdgeLabels || isEdgeSelected || isConnectedToSelectedNode) {
        const midX = Math.round((src.x + tgt.x) / 2);
        const midY = Math.round((src.y + tgt.y) / 2);
        const edgeText = document.createElementNS(SVG_NS, "text");
        edgeText.setAttribute("x", String(midX));
        edgeText.setAttribute("y", String(midY - 4));
        edgeText.setAttribute("text-anchor", "middle");
        edgeText.setAttribute("font-size", "8.5");
        edgeText.setAttribute("fill", isEdgeSelected || isConnectedToSelectedNode ? "#60a5fa" : "#94a3b8");
        edgeText.textContent = edge.relationship_type;
        edgeGroup.appendChild(edgeText);
      }

      const handleSelectEdge = (evt) => {
        evt.stopPropagation();
        this.selectedEdgeId = edge.edge_id;
        this.selectedNodeId = null;
        this.render(this.nodes, this.edges);
        if (this.onSelectEdge) this.onSelectEdge(edge);
      };

      edgeGroup.addEventListener("click", handleSelectEdge);
      edgeGroup.addEventListener("keydown", (evt) => {
        if (evt.key === "Enter" || evt.key === " ") {
          evt.preventDefault();
          handleSelectEdge(evt);
        }
      });

      viewport.appendChild(edgeGroup);
    });

    // 4. Render Nodes
    nodes.forEach((node) => {
      const p = posMap[node.entity_id];
      const isSelected = this.selectedNodeId === node.entity_id;
      const isDimmed =
        this.selectedNodeId && !neighborIds.has(node.entity_id);

      const g = document.createElementNS(SVG_NS, "g");
      g.setAttribute("class", "cursor-pointer focus:outline-none");
      g.setAttribute("tabindex", "0");
      g.setAttribute("role", "button");
      g.setAttribute(
        "aria-label",
        `${node.entity_type} entity ${node.canonical_name}, degree ${node.degree}`
      );
      g.setAttribute("opacity", isDimmed ? "0.3" : "1");

      const radius = Math.min(18, Math.max(9, 8 + node.degree * 1.3));
      const fillHex = (ENTITY_PALETTE[node.entity_type] || ENTITY_PALETTE.CONCEPT).hex;

      if (isSelected) {
        const halo = document.createElementNS(SVG_NS, "circle");
        halo.setAttribute("cx", String(p.x));
        halo.setAttribute("cy", String(p.y));
        halo.setAttribute("r", String(radius + 5));
        halo.setAttribute("fill", "none");
        halo.setAttribute("stroke", "#60a5fa");
        halo.setAttribute("stroke-width", "2.5");
        g.appendChild(halo);
      }

      const circle = document.createElementNS(SVG_NS, "circle");
      circle.setAttribute("cx", String(p.x));
      circle.setAttribute("cy", String(p.y));
      circle.setAttribute("r", String(radius));
      circle.setAttribute("fill", fillHex);
      circle.setAttribute("stroke", isSelected ? "#ffffff" : "#0f172a");
      circle.setAttribute("stroke-width", isSelected ? "2.5" : "2");

      const label = document.createElementNS(SVG_NS, "text");
      label.setAttribute("x", String(p.x));
      label.setAttribute("y", String(p.y + radius + 12));
      label.setAttribute("fill", isSelected ? "#60a5fa" : "#e2e8f0");
      label.setAttribute("font-size", isSelected ? "11" : "10");
      label.setAttribute("font-weight", isSelected ? "700" : "500");
      label.setAttribute("text-anchor", "middle");
      label.textContent =
        node.canonical_name.length > 24
          ? node.canonical_name.slice(0, 22) + "…"
          : node.canonical_name;

      g.appendChild(circle);
      g.appendChild(label);

      const handleSelectNode = (evt) => {
        evt.stopPropagation();
        this.selectedNodeId = node.entity_id;
        this.selectedEdgeId = null;
        this.render(this.nodes, this.edges);
        if (this.onSelectNode) this.onSelectNode(node);
      };

      g.addEventListener("click", handleSelectNode);
      g.addEventListener("keydown", (evt) => {
        if (evt.key === "Enter" || evt.key === " ") {
          evt.preventDefault();
          handleSelectNode(evt);
        }
      });

      viewport.appendChild(g);
    });
  }
}
