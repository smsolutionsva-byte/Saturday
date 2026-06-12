import * as THREE from "three";
import {GLTFLoader} from "three/addons/loaders/GLTFLoader.js";

const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

function numberFromDataset(element, key, fallback) {
  const value = Number(element.dataset[key]);
  return Number.isFinite(value) ? value : fallback;
}

function animationChoices(element) {
  return (element.dataset.animation || "")
    .split(",")
    .map(name => name.trim().toLowerCase())
    .filter(Boolean);
}

function pickAnimation(animations, choices) {
  if (!animations.length) return null;
  for (const choice of choices) {
    const clip = animations.find(animation => animation.name.toLowerCase() === choice);
    if (clip) return clip;
  }
  return animations.find(animation => animation.name.toLowerCase() === "idle") || animations[0];
}

class MascotViewer {
  constructor(element) {
    this.element = element;
    this.clock = new THREE.Clock();
    this.frameId = 0;
    this.size = new THREE.Vector3(1, 1, 1);
    this.targetHeight = 2.05;
    this.frameCenterY = 0;

    this.scene = new THREE.Scene();
    this.camera = new THREE.PerspectiveCamera(26, 1, 0.01, 100);
    this.renderer = new THREE.WebGLRenderer({alpha: true, antialias: true});
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    this.renderer.outputColorSpace = THREE.SRGBColorSpace;
    this.renderer.domElement.className = "mascot-canvas";

    element.prepend(this.renderer.domElement);

    const hemi = new THREE.HemisphereLight(0xffffff, 0x31405a, 2.8);
    const key = new THREE.DirectionalLight(0xffffff, 3.1);
    const rim = new THREE.DirectionalLight(0x7dd8ff, 1.6);
    key.position.set(2.8, 4.2, 4.5);
    rim.position.set(-3, 2.4, -2.8);
    this.scene.add(hemi, key, rim);

    this.resizeObserver = new ResizeObserver(() => this.resize());
    this.resizeObserver.observe(element);
  }

  async init() {
    try {
      const gltf = await new GLTFLoader().loadAsync(this.element.dataset.model);
      this.model = gltf.scene;
      this.model.rotation.y = numberFromDataset(this.element, "modelYaw", 0);
      this.scene.add(this.model);
      this.fitModel();

      const clip = pickAnimation(gltf.animations || [], animationChoices(this.element));
      if (clip && !prefersReducedMotion) {
        this.mixer = new THREE.AnimationMixer(this.model);
        this.mixer.clipAction(clip).reset().play();
      }

      this.resize();
      this.element.classList.add("is-ready");
      this.render();
    } catch (error) {
      console.warn("Saturday mascot model could not load.", error);
      this.element.classList.add("is-error");
    }
  }

  fitModel() {
    const bounds = new THREE.Box3().setFromObject(this.model);
    const center = bounds.getCenter(new THREE.Vector3());
    this.size = bounds.getSize(new THREE.Vector3());
    const height = Math.max(this.size.y, 0.001);
    this.targetHeight = numberFromDataset(this.element, "targetHeight", 2.05);
    this.frameCenterY = numberFromDataset(this.element, "centerY", -0.08);
    const scale = this.targetHeight / height;

    this.model.scale.setScalar(scale);
    this.model.position.x -= center.x * scale;
    this.model.position.z -= center.z * scale;
    this.model.position.y += this.frameCenterY - center.y * scale;
    this.size.multiplyScalar(scale);
  }

  resize() {
    const rect = this.element.getBoundingClientRect();
    const width = Math.max(1, Math.floor(rect.width));
    const height = Math.max(1, Math.floor(rect.height));
    const aspect = width / height;
    this.renderer.setSize(width, height, false);
    this.camera.aspect = aspect;

    const frameScale = numberFromDataset(this.element, "frameScale", 1.2);
    const verticalDistance = (this.size.y * frameScale) / (2 * Math.tan(THREE.MathUtils.degToRad(this.camera.fov * 0.5)));
    const horizontalDistance = (this.size.x * frameScale) / (2 * Math.tan(THREE.MathUtils.degToRad(this.camera.fov * 0.5)) * aspect);
    const distance = Math.max(verticalDistance, horizontalDistance, 2.2);
    const targetY = this.frameCenterY + this.targetHeight * numberFromDataset(this.element, "targetY", 0.02);
    const cameraYaw = numberFromDataset(this.element, "cameraYaw", 0);
    const cameraPitch = numberFromDataset(this.element, "cameraPitch", 0.06);

    this.camera.position.set(
      Math.sin(cameraYaw) * distance,
      targetY + distance * cameraPitch,
      Math.cos(cameraYaw) * distance
    );
    this.camera.lookAt(0, targetY, 0);
    this.camera.updateProjectionMatrix();
  }

  render() {
    this.frameId = requestAnimationFrame(() => this.render());
    const delta = Math.min(this.clock.getDelta(), 0.05);
    if (this.mixer) this.mixer.update(delta);
    this.renderer.render(this.scene, this.camera);
  }
}

for (const element of document.querySelectorAll(".mascot-viewer[data-model]")) {
  new MascotViewer(element).init();
}
