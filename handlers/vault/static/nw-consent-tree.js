// Resolves the node keys the owner can reach and describes the tree for the
// consent screen. Pure functions: no DOM and no network.

import { ROOT_COLLECTIONS, createGrant, decryptFacet, unwrapNodeKey } from "./nw-nodes.js";
import { decodeBase64Url, sealOpen } from "./nw-primitives.js";

function readName(node, nodeKey) {
  const facetZero = node.content.find((entry) => entry.facet === 0);
  if (!facetZero) {
    return "Untitled";
  }
  try {
    const value = decryptFacet(nodeKey, node, 0, decodeBase64Url(facetZero.ciphertext));
    return String(value.name);
  } catch (error) {
    return "Unreadable";
  }
}

function openRootKeys(tree, identity) {
  const index = new Map();
  const nodesById = new Map(tree.nodes.map((node) => [node.id, node]));
  for (const grant of tree.grants) {
    const node = nodesById.get(grant.nodeId);
    if (!node || node.kind !== "root") {
      continue;
    }
    const key = sealOpen(identity.encPub, identity.encSec, decodeBase64Url(grant.wrappedKeys));
    index.set(node.id, { node, key });
  }
  return index;
}

function unwrapChild(index, node) {
  const parent = index.get(node.parentId);
  if (!parent || !node.wrappedKey) {
    return null;
  }
  const info = { id: node.id, parentId: node.parentId, epoch: node.epoch, parentEpoch: parent.node.epoch };
  try {
    return unwrapNodeKey(parent.key, decodeBase64Url(node.wrappedKey), info);
  } catch (error) {
    return null;
  }
}

// buildKeyIndex maps every reachable node id to its node and key, opening the
// roots with the identity key and walking down through wrapped child keys.
export function buildKeyIndex(tree, identity) {
  const index = openRootKeys(tree, identity);
  let progressed = true;
  while (progressed) {
    progressed = false;
    for (const node of tree.nodes) {
      if (index.has(node.id)) {
        continue;
      }
      const key = unwrapChild(index, node);
      if (key !== null) {
        index.set(node.id, { node, key });
        progressed = true;
      }
    }
  }
  return index;
}

// describeCollections lists, per collection, its root and its containers with
// readable names and nesting depth.
export function describeCollections(tree, index) {
  const described = {};
  for (const collection of ROOT_COLLECTIONS) {
    const root = tree.nodes.find((node) => node.kind === "root" && node.collection === collection);
    if (root && index.has(root.id)) {
      described[collection] = { root: describeNode(index, root, 0), containers: describeContainers(tree, index, root) };
    }
  }
  return described;
}

function describeNode(index, node, depth) {
  const entry = index.get(node.id);
  return { id: node.id, name: readName(node, entry.key), depth, collection: node.collection };
}

function describeContainers(tree, index, root) {
  const children = new Map();
  for (const node of tree.nodes) {
    if (node.kind === "container" && index.has(node.id)) {
      const siblings = childrenOf(children, node.parentId);
      siblings.push(node);
      children.set(node.parentId, siblings);
    }
  }
  const ordered = [];
  collectDescendants(index, children, root.id, 1, ordered);
  return ordered;
}

function childrenOf(children, parentId) {
  if (children.has(parentId)) {
    return children.get(parentId);
  }
  return [];
}

function collectDescendants(index, children, parentId, depth, ordered) {
  for (const node of childrenOf(children, parentId)) {
    ordered.push(describeNode(index, node, depth));
    collectDescendants(index, children, node.id, depth + 1, ordered);
  }
}

// selectedNodeIds turns a collection's selection into the node ids to grant.
// Choosing the whole collection selects its root, which covers the subtree.
export function selectedNodeIds(collectionTree, selection) {
  if (selection.whole) {
    return [collectionTree.root.id];
  }
  return [...selection.nodeIds];
}

// buildInstallGrants creates one signed install grant per selected node.
export function buildInstallGrants({ selections, collectionTrees, roles, index, install, granter, certId }) {
  const grants = [];
  for (const [collection, selection] of Object.entries(selections)) {
    for (const nodeId of selectedNodeIds(collectionTrees[collection], selection)) {
      const entry = index.get(nodeId);
      grants.push(createGrant({
        nodeId, nodeKey: entry.key, epoch: entry.node.epoch, role: roles[collection],
        principalType: "install", principalId: install.id, principalEncPub: decodeBase64Url(install.encPub),
        granter, certId,
      }));
    }
  }
  return grants;
}
