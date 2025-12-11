/**
 * MapLibre GL Basemap Configuration for Cortex
 *
 * Phase 2: Dark theme basemap with streets and building footprints
 *
 * Supports multiple free providers:
 * - CartoDB Dark Matter (recommended - no API key required)
 * - MapTiler (100k tiles/month free)
 * - Stadia Maps (200k tiles/month free)
 * - Self-hosted OpenMapTiles
 */

'use strict';

// =============================================================================
// BASEMAP STYLE URLs
// =============================================================================

const BASEMAP_STYLES = {
    // CartoDB Dark Matter - Free, no API key required
    carto_dark: 'https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json',

    // CartoDB Voyager Dark (alternative)
    carto_voyager_dark: 'https://basemaps.cartocdn.com/gl/voyager-gl-style/style.json',

    // MapTiler - Requires API key (100k tiles/month free)
    // Replace YOUR_MAPTILER_KEY with actual key
    maptiler_dark: 'https://api.maptiler.com/maps/dataviz-dark/style.json?key=YOUR_MAPTILER_KEY',
    maptiler_toner: 'https://api.maptiler.com/maps/toner-v2/style.json?key=YOUR_MAPTILER_KEY',

    // Stadia Maps - Requires API key (200k tiles/month free)
    stadia_dark: 'https://tiles.stadiamaps.com/styles/alidade_smooth_dark.json',
    stadia_toner: 'https://tiles.stadiamaps.com/styles/stamen_toner.json'
};

// =============================================================================
// CORTEX CUSTOM DARK STYLE
// =============================================================================

/**
 * Custom dark style matching Cortex visual theme
 * Uses CartoDB vector tiles (free, no key required)
 */
const CORTEX_DARK_STYLE = {
    version: 8,
    name: 'Cortex Dark',
    glyphs: 'https://fonts.openmaptiles.org/{fontstack}/{range}.pbf',
    sprite: 'https://openmaptiles.github.io/osm-bright-gl-style/sprite',

    sources: {
        'carto': {
            type: 'vector',
            tiles: [
                'https://a.basemaps.cartocdn.com/vector/carto.streets/v1/{z}/{x}/{y}.mvt',
                'https://b.basemaps.cartocdn.com/vector/carto.streets/v1/{z}/{x}/{y}.mvt',
                'https://c.basemaps.cartocdn.com/vector/carto.streets/v1/{z}/{x}/{y}.mvt'
            ],
            maxzoom: 16
        }
    },

    layers: [
        // Background - Deep dark matching Cortex theme (#0a0a15)
        {
            id: 'background',
            type: 'background',
            paint: {
                'background-color': '#0a0a15'
            }
        },

        // Landcover - Slightly lighter for parks/vegetation
        {
            id: 'landcover-grass',
            type: 'fill',
            source: 'carto',
            'source-layer': 'landcover',
            filter: ['==', 'class', 'grass'],
            paint: {
                'fill-color': '#0d1210',
                'fill-opacity': 0.8
            }
        },

        // Water - Dark blue tint
        {
            id: 'water',
            type: 'fill',
            source: 'carto',
            'source-layer': 'water',
            paint: {
                'fill-color': '#0d0d1a',
                'fill-opacity': 1
            }
        },

        // Water outline
        {
            id: 'water-outline',
            type: 'line',
            source: 'carto',
            'source-layer': 'water',
            paint: {
                'line-color': '#1a1a2e',
                'line-width': 0.5
            }
        },

        // Buildings - Dark gray fill with subtle visibility
        {
            id: 'buildings',
            type: 'fill',
            source: 'carto',
            'source-layer': 'building',
            minzoom: 13,
            paint: {
                'fill-color': '#1a1a28',
                'fill-opacity': [
                    'interpolate', ['linear'], ['zoom'],
                    13, 0,
                    14, 0.4,
                    16, 0.8
                ]
            }
        },

        // Building outlines - visible at higher zooms
        {
            id: 'building-outline',
            type: 'line',
            source: 'carto',
            'source-layer': 'building',
            minzoom: 15,
            paint: {
                'line-color': '#2a2a3a',
                'line-width': [
                    'interpolate', ['linear'], ['zoom'],
                    15, 0.3,
                    18, 1
                ]
            }
        },

        // 3D Buildings (extrusion) - for dramatic effect
        {
            id: 'building-3d',
            type: 'fill-extrusion',
            source: 'carto',
            'source-layer': 'building',
            minzoom: 15,
            paint: {
                'fill-extrusion-color': '#1a1a28',
                'fill-extrusion-height': [
                    'interpolate', ['linear'], ['zoom'],
                    15, 0,
                    16, ['get', 'render_height']
                ],
                'fill-extrusion-opacity': [
                    'interpolate', ['linear'], ['zoom'],
                    15, 0,
                    16, 0.6
                ]
            }
        },

        // Minor streets - Subtle dark lines
        {
            id: 'streets-minor',
            type: 'line',
            source: 'carto',
            'source-layer': 'transportation',
            filter: ['all',
                ['in', 'class', 'minor', 'service', 'path'],
                ['!=', 'brunnel', 'tunnel']
            ],
            paint: {
                'line-color': '#1a1a28',
                'line-width': [
                    'interpolate', ['linear'], ['zoom'],
                    12, 0.3,
                    14, 1,
                    18, 3
                ]
            }
        },

        // Secondary/Tertiary roads
        {
            id: 'streets-secondary',
            type: 'line',
            source: 'carto',
            'source-layer': 'transportation',
            filter: ['all',
                ['in', 'class', 'secondary', 'tertiary'],
                ['!=', 'brunnel', 'tunnel']
            ],
            paint: {
                'line-color': '#252535',
                'line-width': [
                    'interpolate', ['linear'], ['zoom'],
                    10, 0.5,
                    14, 2,
                    18, 5
                ]
            }
        },

        // Primary roads
        {
            id: 'streets-primary',
            type: 'line',
            source: 'carto',
            'source-layer': 'transportation',
            filter: ['all',
                ['==', 'class', 'primary'],
                ['!=', 'brunnel', 'tunnel']
            ],
            paint: {
                'line-color': '#2a2a3a',
                'line-width': [
                    'interpolate', ['linear'], ['zoom'],
                    8, 0.5,
                    12, 2,
                    18, 6
                ]
            }
        },

        // Highways/Motorways - Most visible roads
        {
            id: 'streets-highway',
            type: 'line',
            source: 'carto',
            'source-layer': 'transportation',
            filter: ['all',
                ['in', 'class', 'motorway', 'trunk'],
                ['!=', 'brunnel', 'tunnel']
            ],
            paint: {
                'line-color': '#3a3a4a',
                'line-width': [
                    'interpolate', ['linear'], ['zoom'],
                    6, 0.5,
                    10, 2,
                    14, 4,
                    18, 8
                ]
            }
        },

        // Highway casing (outline)
        {
            id: 'streets-highway-casing',
            type: 'line',
            source: 'carto',
            'source-layer': 'transportation',
            filter: ['all',
                ['in', 'class', 'motorway', 'trunk'],
                ['!=', 'brunnel', 'tunnel']
            ],
            paint: {
                'line-color': '#4a4a5a',
                'line-width': [
                    'interpolate', ['linear'], ['zoom'],
                    6, 1,
                    10, 3,
                    14, 6,
                    18, 10
                ],
                'line-gap-width': 0
            }
        },

        // Bridges
        {
            id: 'bridges',
            type: 'line',
            source: 'carto',
            'source-layer': 'transportation',
            filter: ['==', 'brunnel', 'bridge'],
            paint: {
                'line-color': '#3a3a4a',
                'line-width': [
                    'interpolate', ['linear'], ['zoom'],
                    10, 1,
                    16, 4
                ]
            }
        },

        // Railways
        {
            id: 'railways',
            type: 'line',
            source: 'carto',
            'source-layer': 'transportation',
            filter: ['==', 'class', 'rail'],
            paint: {
                'line-color': '#3a3a4a',
                'line-width': 1,
                'line-dasharray': [3, 3]
            }
        },

        // Road labels - Only major roads
        {
            id: 'road-labels-major',
            type: 'symbol',
            source: 'carto',
            'source-layer': 'transportation_name',
            filter: ['in', 'class', 'motorway', 'trunk', 'primary'],
            minzoom: 14,
            layout: {
                'text-field': ['get', 'name'],
                'text-size': [
                    'interpolate', ['linear'], ['zoom'],
                    14, 9,
                    18, 12
                ],
                'text-font': ['Open Sans Regular'],
                'symbol-placement': 'line',
                'text-rotation-alignment': 'map',
                'text-max-angle': 30
            },
            paint: {
                'text-color': '#5a5a6a',
                'text-halo-color': '#0a0a15',
                'text-halo-width': 1.5
            }
        },

        // Place labels - Cities/Towns
        {
            id: 'place-labels',
            type: 'symbol',
            source: 'carto',
            'source-layer': 'place',
            filter: ['in', 'class', 'city', 'town'],
            minzoom: 8,
            layout: {
                'text-field': ['get', 'name'],
                'text-size': [
                    'interpolate', ['linear'], ['zoom'],
                    8, 10,
                    12, 14,
                    16, 18
                ],
                'text-font': ['Open Sans Bold'],
                'text-anchor': 'center',
                'text-max-width': 8
            },
            paint: {
                'text-color': '#6a6a7a',
                'text-halo-color': '#0a0a15',
                'text-halo-width': 2
            }
        },

        // Neighborhood labels
        {
            id: 'neighborhood-labels',
            type: 'symbol',
            source: 'carto',
            'source-layer': 'place',
            filter: ['in', 'class', 'suburb', 'neighbourhood'],
            minzoom: 13,
            layout: {
                'text-field': ['get', 'name'],
                'text-size': 11,
                'text-font': ['Open Sans Regular'],
                'text-anchor': 'center',
                'text-transform': 'uppercase',
                'text-letter-spacing': 0.1
            },
            paint: {
                'text-color': '#4a4a5a',
                'text-halo-color': '#0a0a15',
                'text-halo-width': 1
            }
        }
    ]
};

// =============================================================================
// STYLE CONFIGURATION HELPERS
// =============================================================================

/**
 * Get the recommended basemap style for Cortex
 * Uses custom style if CartoDB tiles are available, falls back to hosted styles
 */
function getCortexMapStyle(options = {}) {
    const { provider, apiKey } = options;

    // Default: Use our custom Cortex dark style (free, no key)
    if (!provider || provider === 'cortex' || provider === 'custom') {
        return CORTEX_DARK_STYLE;
    }

    // MapTiler (requires API key)
    if (provider === 'maptiler' && apiKey) {
        return BASEMAP_STYLES.maptiler_dark.replace('YOUR_MAPTILER_KEY', apiKey);
    }

    // Stadia Maps
    if (provider === 'stadia') {
        return BASEMAP_STYLES.stadia_dark;
    }

    // CartoDB hosted style (fallback)
    return BASEMAP_STYLES.carto_dark;
}

/**
 * Create a simplified style for lower zoom levels / performance
 */
function getSimplifiedStyle() {
    return {
        version: 8,
        name: 'Cortex Simple',
        sources: {
            'carto': {
                type: 'vector',
                tiles: [
                    'https://a.basemaps.cartocdn.com/vector/carto.streets/v1/{z}/{x}/{y}.mvt'
                ],
                maxzoom: 14
            }
        },
        layers: [
            {
                id: 'background',
                type: 'background',
                paint: { 'background-color': '#0a0a15' }
            },
            {
                id: 'water',
                type: 'fill',
                source: 'carto',
                'source-layer': 'water',
                paint: { 'fill-color': '#0d0d1a' }
            },
            {
                id: 'streets',
                type: 'line',
                source: 'carto',
                'source-layer': 'transportation',
                paint: {
                    'line-color': '#2a2a3a',
                    'line-width': 1
                }
            }
        ]
    };
}

/**
 * Modify existing style to match Cortex theme colors
 */
function applyCortexTheme(style) {
    if (typeof style === 'string') {
        // Style URL - can't modify directly
        console.warn('Cannot apply Cortex theme to style URL, use custom style instead');
        return style;
    }

    const modified = JSON.parse(JSON.stringify(style));

    // Find and modify background layer
    const bgLayer = modified.layers.find(l => l.id === 'background');
    if (bgLayer) {
        bgLayer.paint['background-color'] = '#0a0a15';
    }

    // Find and modify water layer
    const waterLayer = modified.layers.find(l => l.id === 'water' || l['source-layer'] === 'water');
    if (waterLayer && waterLayer.paint) {
        waterLayer.paint['fill-color'] = '#0d0d1a';
    }

    return modified;
}

// =============================================================================
// LAYER VISIBILITY CONTROLS
// =============================================================================

/**
 * Toggle building visibility on a MapLibre map
 */
function toggleBuildings(map, visible) {
    const buildingLayers = ['buildings', 'building-outline', 'building-3d'];
    buildingLayers.forEach(layerId => {
        if (map.getLayer(layerId)) {
            map.setLayoutProperty(layerId, 'visibility', visible ? 'visible' : 'none');
        }
    });
}

/**
 * Toggle street labels visibility
 */
function toggleStreetLabels(map, visible) {
    const labelLayers = ['road-labels-major', 'place-labels', 'neighborhood-labels'];
    labelLayers.forEach(layerId => {
        if (map.getLayer(layerId)) {
            map.setLayoutProperty(layerId, 'visibility', visible ? 'visible' : 'none');
        }
    });
}

/**
 * Set building opacity (0-1)
 */
function setBuildingOpacity(map, opacity) {
    if (map.getLayer('buildings')) {
        map.setPaintProperty('buildings', 'fill-opacity', opacity);
    }
    if (map.getLayer('building-3d')) {
        map.setPaintProperty('building-3d', 'fill-extrusion-opacity', opacity);
    }
}

// =============================================================================
// EXPORTS
// =============================================================================

if (typeof window !== 'undefined') {
    window.BASEMAP_STYLES = BASEMAP_STYLES;
    window.CORTEX_DARK_STYLE = CORTEX_DARK_STYLE;
    window.getCortexMapStyle = getCortexMapStyle;
    window.getSimplifiedStyle = getSimplifiedStyle;
    window.applyCortexTheme = applyCortexTheme;
    window.toggleBuildings = toggleBuildings;
    window.toggleStreetLabels = toggleStreetLabels;
    window.setBuildingOpacity = setBuildingOpacity;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        BASEMAP_STYLES,
        CORTEX_DARK_STYLE,
        getCortexMapStyle,
        getSimplifiedStyle,
        applyCortexTheme,
        toggleBuildings,
        toggleStreetLabels,
        setBuildingOpacity
    };
}
