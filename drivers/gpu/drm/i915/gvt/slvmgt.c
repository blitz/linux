/* Copyright Cyberus Technology GmbH *
 *        All rights reserved        */

/* SPDX-License-Identifier: GPL-2.0  */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <drm/i915_slvmgt.h>
#include <linux/module.h>

#include "i915_drv.h"
#include "gvt.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cyberus Technology GmbH");
MODULE_DESCRIPTION("SuperNOVA Linux Virtualization Module GVT-g Support");

/*
 * See slvmgt_host_init. If intel_gvt_ops is NULL, then graphics virtualization
 * capabilities are not available.
 */
static const struct intel_gvt_ops *intel_gvt_ops;
static struct intel_gvt *gvt;

struct slvmgt_vdev {
	struct intel_vgpu *vgpu;
	int port;
};

/*
 * HELPERS
 */

static inline struct slvmgt_vdev *slvmgt_vdev(struct intel_vgpu *vgpu)
{
	return intel_vgpu_vdev(vgpu);
}

static struct intel_vgpu_type *
slvmgt_get_vgpu_type(enum slvmgt_vgpu_type vgpu_type)
{
	char type_name[64];
	int desired_type = 0;

	if (!gvt)
		goto err;

	if (!gvt->types)
		goto err;

	switch (vgpu_type) {
	case SLVMGT_VGPU_TYPE_64M:
		desired_type = 0;
		break;
	case SLVMGT_VGPU_TYPE_128M:
		desired_type = 1;
		break;
	default:
		goto err;
	}

	desired_type = (desired_type >= gvt->num_types) ? gvt->num_types - 1 : desired_type;

	/*
	 * This is somewhat unsophisticated and we rely on the vGPU types to be
	 * ordered by their amount of vRAM.
	 *
	 * Entry 0 is 64MB, entry 1 is 128MB.
	 */
	snprintf(type_name, sizeof(type_name), "i915-%s",
		 gvt->types[desired_type].name);

	return &gvt->types[desired_type];

err:
	return NULL;
}

static struct slvmgt_vgpu *slvmgt_handle_to_vgpu(unsigned long handle)
{
	struct slvmgt_vgpu *vgpu = (struct slvmgt_vgpu *)handle;

	/*
	 * TODO We might want to do some sanity checking here. The KVMGT module
	 * is also very defensive with these handle values.
	 */

	return vgpu;
}

/*
 * PUBLIC API
 */

int slvmgt_vgpu_create(struct slvmgt_vgpu *vgpu, const struct slvmgt_ops *ops,
		       const struct slvmgt_edid *edid,
		       enum slvmgt_vgpu_type vgpu_type)
{
	struct intel_vgpu_type *intel_vgpu_type;
	int rc;

	/* We need to keep the module alive, while vGPUs exist. */
	if (!try_module_get(THIS_MODULE)) {
		rc = -ENODEV;
		goto err;
	}

	vgpu->slvm = ops;
	spin_lock_init(&vgpu->eventfd_lock);
	vgpu->eventfd_ctx = NULL;

	intel_vgpu_type = slvmgt_get_vgpu_type(vgpu_type);
	if (!intel_vgpu_type) {
		rc = -EINVAL;
		goto err_vgpu_type;
	}

	vgpu->vgpu = intel_gvt_ops->vgpu_create(gvt, intel_vgpu_type);
	if (IS_ERR(vgpu->vgpu)) {
		rc = PTR_ERR(vgpu->vgpu);
		vgpu->vgpu = NULL;
		goto err_vgpu_create;
	}

	vgpu->vgpu->handle = (unsigned long)vgpu;

	slvmgt_vgpu_set_edid(vgpu, edid);
	intel_gvt_ops->vgpu_activate(vgpu->vgpu);

	return PTR_ERR_OR_ZERO(vgpu->vgpu);

err_vgpu_create:
err_vgpu_type:
	module_put(THIS_MODULE);
err:
	return rc;
}
EXPORT_SYMBOL_GPL(slvmgt_vgpu_create);

void slvmgt_vgpu_destroy(struct slvmgt_vgpu *vgpu)
{
	intel_gvt_ops->vgpu_deactivate(vgpu->vgpu);

	/*
	 * Xengt doesn't call vgpu_release, so we hopefully don't need
	 * it either.
	 */
	intel_gvt_ops->vgpu_destroy(vgpu->vgpu);

	if (vgpu->eventfd_ctx)
		eventfd_ctx_put(vgpu->eventfd_ctx);

	module_put(THIS_MODULE);
}
EXPORT_SYMBOL_GPL(slvmgt_vgpu_destroy);

/*
 * Basic check for a valid EDID. An invalid EDID can lead to a black
 * screen.
 */
static bool is_valid_edid(const struct slvmgt_edid *edid)
{
	static const char edid_hdr_magic[8] = { 0x00, 0xff, 0xff, 0xff,
						0xff, 0xff, 0xff, 0x00 };

	return memcmp(edid_hdr_magic, edid->data, sizeof(edid_hdr_magic)) == 0;
}

int slvmgt_vgpu_set_edid(struct slvmgt_vgpu *vgpu,
			 const struct slvmgt_edid *edid)
{
	struct intel_vgpu_port *port =
		intel_vgpu_port(vgpu->vgpu, slvmgt_vdev(vgpu->vgpu)->port);
	void *edid_block_ptr = port->edid->edid_block;

	if (!edid || !is_valid_edid(edid) || !edid_block_ptr) {
		goto err;
	}

	memcpy(edid_block_ptr, edid, EDID_LENGTH);
	return 0;

err:
	return -EINVAL;
}
EXPORT_SYMBOL_GPL(slvmgt_vgpu_set_edid);

int slvmgt_vgpu_set_irqfd(struct slvmgt_vgpu *vgpu, struct eventfd_ctx *ctx)
{
	int rc;

	spin_lock(&vgpu->eventfd_lock);

	if (vgpu->eventfd_ctx) {
		eventfd_ctx_put(ctx);
		rc = -EEXIST;
	} else {
		WRITE_ONCE(vgpu->eventfd_ctx, ctx);
		rc = 0;
	}

	spin_unlock(&vgpu->eventfd_lock);

	return rc;
}
EXPORT_SYMBOL_GPL(slvmgt_vgpu_set_irqfd);

int slvmgt_vgpu_forward_access(struct slvmgt_vgpu *vgpu,
			       enum slvmgt_space space, void *data,
			       unsigned long offset, unsigned long size,
			       bool is_write)
{
	int rc = -EINVAL;

	switch (space) {
	case SLVMGT_SPACE_TRACKED_MEM:
		if (is_write) {
			rc = intel_gvt_ops->write_protect_handler(
				vgpu->vgpu, offset, data, size);

			/*
			 * In case there was nothing to track we get ENXIO
			 * back. This can happen when we had a race with the
			 * mediator disabling the tracking or userspace hands in
			 * an untracked page.
			 */
			if (rc == -ENXIO)
				rc = 0;
		} else {
			rc = -EINVAL;
		}

		break;
	case SLVMGT_SPACE_PCI_CONFIG:
		if (is_write)
			rc = intel_gvt_ops->emulate_cfg_write(
				vgpu->vgpu, offset, data, size);
		else
			rc = intel_gvt_ops->emulate_cfg_read(vgpu->vgpu, offset,
							     data, size);

		break;
	case SLVMGT_SPACE_MMIO:
		if (is_write)
			rc = intel_gvt_ops->emulate_mmio_write(
				vgpu->vgpu, offset, data, size);
		else
			rc = intel_gvt_ops->emulate_mmio_read(
				vgpu->vgpu, offset, data, size);
		break;
	}

	return rc;
}
EXPORT_SYMBOL_GPL(slvmgt_vgpu_forward_access);

int slvmgt_vgpu_query_plane(struct slvmgt_vgpu *vgpu,
			    struct vfio_device_gfx_plane_info *plane)
{
	return intel_gvt_ops->vgpu_query_plane(vgpu->vgpu, plane);
}
EXPORT_SYMBOL_GPL(slvmgt_vgpu_query_plane);

int slvmgt_vgpu_get_dmabuf(struct slvmgt_vgpu *vgpu, unsigned int dmabuf_id)
{
	return intel_gvt_ops->vgpu_get_dmabuf(vgpu->vgpu, dmabuf_id);
}
EXPORT_SYMBOL_GPL(slvmgt_vgpu_get_dmabuf);

void slvmgt_vgpu_display_hotplug(struct slvmgt_vgpu *vgpu, bool connected)
{
	intel_gvt_ops->emulate_hotplug(vgpu->vgpu, connected);
}
EXPORT_SYMBOL_GPL(slvmgt_vgpu_display_hotplug);

void slvmgt_vgpu_reset(struct slvmgt_vgpu *vgpu)
{
	intel_gvt_ops->vgpu_reset(vgpu->vgpu);
}
EXPORT_SYMBOL_GPL(slvmgt_vgpu_reset);

/*
 * MEDIATOR BACKEND
 */

/*
 * Initialize graphics virtualization.
 *
 * This function is called by the i915 mediator on startup if graphics
 * virtualization capabilities are present and usable in the system.
 */
static int slvmgt_host_init(struct device *dev, void *generic_gvt,
			    const void *ops)
{
	gvt = generic_gvt;
	intel_gvt_ops = ops;

	return 0;
}

static void slvmgt_host_exit(struct device *dev, void* intel_gvt)
{
	/* We assume that we do not get here as long as vGPUs are around. */
	intel_gvt_ops = NULL;
	gvt = NULL;
}

static int slvmgt_attach_vgpu(void *p_vgpu, unsigned long *handle)
{
	struct intel_vgpu *vgpu = (struct intel_vgpu *)p_vgpu;

	vgpu->vdev = kzalloc(sizeof(struct slvmgt_vdev), GFP_KERNEL);

	if (!vgpu->vdev)
		return -ENOMEM;

	slvmgt_vdev(vgpu)->vgpu = vgpu;
	slvmgt_vdev(vgpu)->port = PORT_NONE;

	return 0;
}

static void slvmgt_detach_vgpu(void *p_vgpu)
{
	struct intel_vgpu *vgpu = (struct intel_vgpu *)p_vgpu;

	kfree(vgpu->vdev);
}

static int slvmgt_inject_msi(unsigned long handle, u32 addr, u16 data)
{
	struct slvmgt_vgpu *vgpu = slvmgt_handle_to_vgpu(handle);
	struct eventfd_ctx *ctx = READ_ONCE(vgpu->eventfd_ctx);

	if (ctx)
		eventfd_signal(ctx, 1);

	return 0;
}

static unsigned long slvmgt_virt_to_pfn(void *addr)
{
	return PFN_DOWN(__pa(addr));
}

static int slvmgt_enable_page_track(unsigned long handle, u64 gfn)
{
	struct slvmgt_vgpu *vgpu = slvmgt_handle_to_vgpu(handle);
	return vgpu->slvm->page_track_set(vgpu, gfn, true);
}

static int slvmgt_disable_page_track(unsigned long handle, u64 gfn)
{
	struct slvmgt_vgpu *vgpu = slvmgt_handle_to_vgpu(handle);
	return vgpu->slvm->page_track_set(vgpu, gfn, false);
}

static int slvmgt_read_gpa(unsigned long handle, unsigned long gpa, void *buf,
			   unsigned long len)
{
	struct slvmgt_vgpu *vgpu = slvmgt_handle_to_vgpu(handle);
	return vgpu->slvm->access_gpa(vgpu, gpa, buf, len, false);
}

static int slvmgt_write_gpa(unsigned long handle, unsigned long gpa, void *buf,
			    unsigned long len)
{
	struct slvmgt_vgpu *vgpu = slvmgt_handle_to_vgpu(handle);
	return vgpu->slvm->access_gpa(vgpu, gpa, buf, len, true);
}

static unsigned long slvmgt_gfn_to_pfn(unsigned long handle, unsigned long gfn)
{
	struct slvmgt_vgpu *vgpu = slvmgt_handle_to_vgpu(handle);
	unsigned long pfn = INTEL_GVT_INVALID_ADDR;
	int rc;

	rc = vgpu->slvm->gfn_to_pfn(vgpu, gfn, &pfn);
	return rc ? INTEL_GVT_INVALID_ADDR : pfn;
}

static int slvmgt_dma_map_guest_page(unsigned long handle, unsigned long gfn,
				     unsigned long size, dma_addr_t *dma_addr)
{
	struct slvmgt_vgpu *vgpu = slvmgt_handle_to_vgpu(handle);
	return vgpu->slvm->dma_map_guest_page(vgpu, gfn, size, dma_addr);
}

static void slvmgt_dma_unmap_guest_page(unsigned long handle,
					dma_addr_t dma_addr)
{
	struct slvmgt_vgpu *vgpu = slvmgt_handle_to_vgpu(handle);
	vgpu->slvm->dma_unmap_guest_page(vgpu, dma_addr);
}

static int slvmgt_dma_pin_guest_page(unsigned long handle, dma_addr_t dma_addr)
{
	struct slvmgt_vgpu *vgpu = slvmgt_handle_to_vgpu(handle);
	return vgpu->slvm->dma_pin_guest_page(vgpu, dma_addr);
}

static int slvmgt_set_opregion(void *p_vgpu)
{
	return 0;
}

static int slvmgt_set_edid(void *p_vgpu, int port_num)
{
	struct intel_vgpu *vgpu = (struct intel_vgpu *)p_vgpu;

	slvmgt_vdev(vgpu)->port = port_num;
	return 0;
}

static bool slvmgt_is_valid_gfn(unsigned long handle, unsigned long gfn)
{
	struct slvmgt_vgpu *vgpu = slvmgt_handle_to_vgpu(handle);
	return vgpu->slvm->is_valid_gfn(vgpu, gfn);
}

static int slvmgt_map_gfn_to_mfn(unsigned long handle, unsigned long gfn,
				 unsigned long mfn, unsigned int nr, bool map)

{
	struct slvmgt_vgpu *vgpu = slvmgt_handle_to_vgpu(handle);
	return vgpu->slvm->map_gfn_to_mfn(vgpu, gfn, mfn, nr, map);
}

static const struct intel_gvt_mpt slvmgt_mpt = {
	/*
	 * We basically behave indistinguishably from Xen, so this fine until
	 * there is finer-grained control to select mediator behavior.
	 */
	.type = INTEL_GVT_HYPERVISOR_XEN,

	.host_init = slvmgt_host_init,
	.host_exit = slvmgt_host_exit,
	.attach_vgpu = slvmgt_attach_vgpu,
	.detach_vgpu = slvmgt_detach_vgpu,
	.inject_msi = slvmgt_inject_msi,
	.from_virt_to_mfn = slvmgt_virt_to_pfn,
	.enable_page_track = slvmgt_enable_page_track,
	.disable_page_track = slvmgt_disable_page_track,
	.read_gpa = slvmgt_read_gpa,
	.write_gpa = slvmgt_write_gpa,
	.gfn_to_mfn = slvmgt_gfn_to_pfn,
	.dma_map_guest_page = slvmgt_dma_map_guest_page,
	.dma_unmap_guest_page = slvmgt_dma_unmap_guest_page,
	.dma_pin_guest_page = slvmgt_dma_pin_guest_page,
	.set_opregion = slvmgt_set_opregion,
	.set_edid = slvmgt_set_edid,
	.is_valid_gfn = slvmgt_is_valid_gfn,
	.map_gfn_to_mfn = slvmgt_map_gfn_to_mfn,
};

/*
 * MEDIATOR BACKEND
 */

static bool hv_backend_registered = false;

static int __init slvmgt_init(void)
{
	int rc;

	rc = intel_gvt_register_hypervisor(&slvmgt_mpt);
	if (rc == 0) {
		hv_backend_registered = true;
	} else if (rc == -ENODEV) {
		pr_info("GVT-based vGPU support is not available. Attaching anyway.\n");

		/*
		 * We attach the SLVMGT module even if no GVT-capable hardware
		 * is found. This allows the SLVM module to work, even when GVT
		 * is not available.
		 *
		 * This is okay, because all GVT calls will be rejected by i915
		 * when no GVT-capable GPU (or no hypervisor backend) is
		 * present.
		 */
		rc = 0;
	}

	return rc;
}

static void __exit slvmgt_cleanup(void)
{
	if (hv_backend_registered) {
		intel_gvt_unregister_hypervisor();
	}
}

module_init(slvmgt_init);
module_exit(slvmgt_cleanup);
