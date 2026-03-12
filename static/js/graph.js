/**
 * Cytoscape.js threat infrastructure graph
 * Converts D3 format to Cytoscape if needed
 */
const NODE_COLORS = {
    domain: '#4da3ff',
    url: '#f97316',
    ip: '#a855f7',
    payload_hash: '#ef4444',
    hash: '#ef4444',
};

function d3ToCytoscape(d3Data) {
    if (!d3Data?.nodes) return null;
    return {
        elements: {
            nodes: d3Data.nodes.map(n => ({
                data: { id: n.id, label: n.label, type: n.type || n.group, color: NODE_COLORS[n.type || n.group] || '#4da3ff' }
            })),
            edges: (d3Data.links || []).map((l, i) => ({
                data: { id: 'e' + i, source: l.source?.id || l.source, target: l.target?.id || l.target, relation: l.relation || '' }
            }))
        }
    };
}

function initGraph(containerId, graphData) {
    if (!window.cytoscape) {
        console.error('Cytoscape.js not loaded');
        return null;
    }

    const container = document.getElementById(containerId);
    if (!container) return null;

    let elements = graphData?.elements;
    if (!elements && graphData?.nodes) {
        graphData = d3ToCytoscape(graphData);
        elements = graphData?.elements;
    }
    if (!elements?.nodes?.length) return null;

    const elementsArray = [
        ...elements.nodes.map(n => ({
            group: 'nodes',
            data: {
                ...(n.data || n),
                id: (n.data || n).id,
                label: (n.data || n).label,
                type: (n.data || n).type,
                color: NODE_COLORS[(n.data || n).type] || '#4da3ff',
            },
        })),
        ...(elements.edges || []).map(e => ({
            group: 'edges',
            data: e.data || { id: e.id, source: e.source, target: e.target },
        })),
    ];

    const cy = cytoscape({
        container: container,
        elements: elementsArray,
        style: [
            {
                selector: 'node',
                style: {
                    'background-color': 'data(color)',
                    'label': 'data(label)',
                    'text-valign': 'bottom',
                    'text-halign': 'center',
                    'font-size': '12px',
                    'font-weight': '600',
                    'color': '#ffffff',
                    'text-outline-color': '#0b1220',
                    'text-outline-width': 3,
                    'text-outline-opacity': 1,
                    'text-background-color': '#0b1220',
                    'text-background-opacity': 1,
                    'text-background-padding': '4px',
                    'text-background-shape': 'round-rectangle',
                    'width': 24,
                    'height': 24,
                    'text-max-width': '120px',
                    'text-wrap': 'ellipsis',
                },
            },
            {
                selector: 'node:selected',
                style: {
                    'border-width': 3,
                    'border-color': '#4da3ff',
                },
            },
            {
                selector: 'node:hover',
                style: {
                    'border-width': 2,
                    'border-color': '#4da3ff',
                },
            },
            {
                selector: 'edge',
                style: {
                    'width': 1,
                    'line-color': 'rgba(77, 163, 255, 0.5)',
                    'target-arrow-color': 'rgba(77, 163, 255, 0.5)',
                    'target-arrow-shape': 'triangle',
                    'curve-style': 'bezier',
                },
            },
        ],
        layout: {
            name: 'cose',
            animate: 'end',
            animationDuration: 500,
            fit: true,
            padding: 40,
        },
        minZoom: 0.2,
        maxZoom: 3,
    });

    cy.one('layoutstop', () => {
        cy.fit(40);
    });

    return cy;
}
