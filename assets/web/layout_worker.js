/** 3D force-directed layout in a Web Worker. */
self.onmessage = function (ev) {
  const { nodes, edges, spread = 400 } = ev.data;
  const positions = {};
  const n = nodes.length || 1;

  nodes.forEach((node, i) => {
    const phi = Math.acos(-1 + (2 * i) / n);
    const theta = Math.sqrt(n * Math.PI) * phi;
    const r = spread * 0.5;
    positions[node.key] = {
      x: r * Math.cos(theta) * Math.sin(phi),
      y: r * Math.sin(theta) * Math.sin(phi),
      z: r * Math.cos(phi),
    };
  });

  for (let iter = 0; iter < 100; iter++) {
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = positions[nodes[i].key];
        const b = positions[nodes[j].key];
        let dx = a.x - b.x, dy = a.y - b.y, dz = a.z - b.z;
        let d = Math.sqrt(dx * dx + dy * dy + dz * dz) || 1;
        const rep = 12000 / (d * d);
        a.x += (dx / d) * rep; a.y += (dy / d) * rep; a.z += (dz / d) * rep;
        b.x -= (dx / d) * rep; b.y -= (dy / d) * rep; b.z -= (dz / d) * rep;
      }
    }
    for (const e of edges) {
      const a = positions[e.source], b = positions[e.target];
      if (!a || !b) continue;
      let dx = b.x - a.x, dy = b.y - a.y, dz = b.z - a.z;
      let d = Math.sqrt(dx * dx + dy * dy + dz * dz) || 1;
      const att = (d - 60) * 0.015;
      a.x += (dx / d) * att; a.y += (dy / d) * att; a.z += (dz / d) * att;
      b.x -= (dx / d) * att; b.y -= (dy / d) * att; b.z -= (dz / d) * att;
    }
  }
  self.postMessage({ positions });
};
