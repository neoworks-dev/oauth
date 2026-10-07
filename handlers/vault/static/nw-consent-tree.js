// Resolves the node keys the owner can reach and describes the tree for the
// consent screen. Pure functions: no DOM and no network.

import { createGrant, createRootNode, grantHead, nextLogPosition, unwrapNodeKey } from "./nw-nodes.js";
import { decodeBase64Url, sealOpen } from "./nw-primitives.js";
import { readTitle } from "./nw-titles.js";

// parseDescriptors maps each collection of the tree's schemas to its registry
// title and parsed node descriptor.
export function parseDescriptors(schemas) {
  const descriptors = {};
  for (const [collection, schema] of Object.entries(schemas || {})) {
    descriptors[collection] = { title: schema.title, descriptor: parsedOrNull(schema.descriptor) };
  }
  return descriptors;
}

function parsedOrNull(text) {
  try {
    return JSON.parse(text);
  } catch (error) {
    return null;
  }
}

// readName is a root's collection title, or another node's title field.
function readName(node, nodeKey, descriptors) {
  const schema = descriptors[node.collection];
  if (!schema) {
    return "Untitled";
  }
  if (node.kind === "root") {
    return rootName(node, schema);
  }
  if (schema.descriptor === null) {
    return "Untitled";
  }
  const title = readTitle(node, nodeKey, schema.descriptor);
  if (title === null || title === "") {
    return "Untitled";
  }
  return title;
}

function rootName(node, schema) {
  if (schema.title) {
    return schema.title;
  }
  return node.collection;
}

function openRootKeys(tree, identity) {
  const index = new Map();
  const nodesById = new Map(tree.nodes.map((node) => [node.id, node]));
  for (const grant of tree.grants) {
    const node = nodesById.get(grant.nodeId);
    if (!node) {
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

// describeCollections lists, for each requested collection the user owns a
// root in, the root (named by its collection's label) and its containers with
// their titles and nesting depth.
export function describeCollections(tree, index, userId, collections, labels) {
  const descriptors = parseDescriptors(tree.schemas);
  const described = {};
  for (const collection of collections) {
    const root = tree.nodes.find((node) => node.kind === "root" && node.collection === collection && node.ownerId === userId);
    if (root && index.has(root.id)) {
      const rootEntry = { id: root.id, name: labels[collection], depth: 0, collection, ownerEmail: root.ownerEmail };
      described[collection] = { root: rootEntry, containers: describeContainers(tree, index, root, descriptors) };
    }
  }
  return described;
}

function describeNode(index, node, depth, descriptors) {
  const entry = index.get(node.id);
  return { id: node.id, name: readName(node, entry.key, descriptors), depth, collection: node.collection, ownerEmail: node.ownerEmail };
}

function describeContainers(tree, index, root, descriptors) {
  const children = new Map();
  for (const node of tree.nodes) {
    if (node.kind === "container" && index.has(node.id)) {
      const siblings = childrenOf(children, node.parentId);
      siblings.push(node);
      children.set(node.parentId, siblings);
    }
  }
  const ordered = [];
  collectDescendants(index, children, root.id, 1, ordered, descriptors);
  return ordered;
}

function childrenOf(children, parentId) {
  if (children.has(parentId)) {
    return children.get(parentId);
  }
  return [];
}

function collectDescendants(index, children, parentId, depth, ordered, descriptors) {
  for (const node of childrenOf(children, parentId)) {
    ordered.push(describeNode(index, node, depth, descriptors));
    collectDescendants(index, children, node.id, depth + 1, ordered, descriptors);
  }
}

// describeSharedNodes lists, per collection, the nodes other people shared with
// the user whose keys the user holds: each entry point and the containers below.
export function describeSharedNodes(tree, index, userId) {
  const descriptors = parseDescriptors(tree.schemas);
  const children = new Map();
  const entries = [];
  for (const node of tree.nodes) {
    if (node.ownerId === userId || !index.has(node.id)) {
      continue;
    }
    if (index.has(node.parentId)) {
      children.set(node.parentId, [...childrenOf(children, node.parentId), node]);
    } else {
      entries.push(node);
    }
  }
  const described = new Map();
  for (const entry of entries) {
    const ordered = [describeNode(index, entry, 0, descriptors)];
    collectDescendants(index, children, entry.id, 1, ordered, descriptors);
    described.set(entry.collection, [...childrenOf(described, entry.collection), ...ordered]);
  }
  return Object.fromEntries(described);
}

// planNewRoots creates a root, and the user's own grant on it as entry 0 of its
// access log, for each requested collection the user has none in yet. It
// returns the roots as the consent sends them, plus what the consent tree needs
// to grant on them: their keys, their log heads and a description of each.
export function planNewRoots({ collections, collectionTrees, userId, identity, labels }) {
  const planned = { roots: [], keys: new Map(), heads: {}, trees: {} };
  for (const collection of collections) {
    if (collectionTrees[collection]) {
      continue;
    }
    const { node, nodeKey } = createRootNode({ userId, collection, identity });
    const grant = createGrant({
      nodeId: node.id, nodeKey, epoch: node.epoch, role: "write", principalType: "user", principalId: userId,
      principalEncPub: identity.encPub, granter: { userId, signSec: identity.signSec }, position: nextLogPosition(null),
    });
    planned.roots.push({ node, grant });
    planned.keys.set(node.id, { node, key: nodeKey });
    planned.heads[node.id] = grantHead(grant);
    const rootEntry = { id: node.id, name: labels[collection], depth: 0, collection };
    planned.trees[collection] = { root: rootEntry, containers: [] };
  }
  return planned;
}

// heldRoles maps every shared node the user can open to the highest role the
// user's grants give on it, inherited from the nearest granted ancestor.
export function heldRoles(tree, index) {
  const grantRoles = new Map(tree.grants.map((grant) => [grant.nodeId, grant.role]));
  const roles = new Map();
  for (const [nodeId] of index) {
    roles.set(nodeId, inheritedRole(index, grantRoles, nodeId));
  }
  return roles;
}

function inheritedRole(index, grantRoles, nodeId) {
  let best = null;
  let current = nodeId;
  while (current && index.has(current)) {
    const role = grantRoles.get(current);
    if (role === "write" || (role !== undefined && best === null)) {
      best = role;
    }
    current = index.get(current).node.parentId;
  }
  return best;
}

// selectedNodeIds turns a collection's selection into the node ids to grant.
// Choosing the whole collection selects its root, which covers the subtree.
export function selectedNodeIds(collectionTree, selection) {
  if (selection.whole) {
    return [collectionTree.root.id];
  }
  return [...selection.nodeIds];
}

// buildInstallGrants creates one signed install grant per selected node, each
// extending that node's access log head.
export function buildInstallGrants({ selections, collectionTrees, roles, held, userId, index, heads, install, granter, certId }) {
  const grants = [];
  for (const [collection, selection] of Object.entries(selections)) {
    for (const nodeId of selectedNodeIds(collectionTrees[collection], selection)) {
      const entry = index.get(nodeId);
      grants.push(createGrant({
        nodeId, nodeKey: entry.key, epoch: entry.node.epoch, role: grantRole(roles[collection], entry.node, held.get(nodeId), userId),
        principalType: "install", principalId: install.id, principalEncPub: decodeBase64Url(install.encPub),
        granter, certId, position: nextLogPosition(heads[nodeId]),
      }));
    }
  }
  return grants;
}

// grantRole caps the requested role at the role the user holds on a node they
// don't own, so a user passes a share on to their own app but never beyond it.
function grantRole(requestedRole, node, heldRole, userId) {
  if (node.ownerId === userId || heldRole === "write") {
    return requestedRole;
  }
  return "read";
}
