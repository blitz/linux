#include "i915_drv.h"
#include "gvt.h"

struct intel_gvt *intel_gvt_from_kdev(struct device *kobj)
{
	return kdev_to_i915(kobj)->gvt;
}
EXPORT_SYMBOL_GPL(intel_gvt_from_kdev);

void *intel_vgpu_vdev(struct intel_vgpu *vgpu)
{
	return vgpu->vdev;
}
EXPORT_SYMBOL_GPL(intel_vgpu_vdev);

void intel_vgpu_set_vdev(struct intel_vgpu *vgpu, void *vdev)
{
	vgpu->vdev = vdev;
}
EXPORT_SYMBOL_GPL(intel_vgpu_set_vdev);

int intel_vgpu_id(struct intel_vgpu *vgpu)
{
	return vgpu->id;
}
EXPORT_SYMBOL_GPL(intel_vgpu_id);

unsigned intel_vgpu_hw_id(struct intel_vgpu *vgpu)
{
	return vgpu->submission.shadow[0]->gem_context->hw_id;
}
EXPORT_SYMBOL_GPL(intel_vgpu_hw_id);

bool intel_vgpu_active_find(struct intel_vgpu *vgpu, bool (*pred)(struct intel_vgpu *, void *), void *ctx)
{
	struct intel_vgpu *itr;
	int id;
	bool ret = false;

	mutex_lock(&vgpu->gvt->lock);
	for_each_active_vgpu(vgpu->gvt, itr, id) {
		if (pred(itr, ctx)) {
			ret = true;
			goto out;
		}
	}
 out:
	mutex_unlock(&vgpu->gvt->lock);
	return ret;
}
EXPORT_SYMBOL_GPL(intel_vgpu_active_find);

struct device *intel_vgpu_pdev(struct intel_vgpu *vgpu)
{
	return &vgpu->gvt->dev_priv->drm.pdev->dev;
}
EXPORT_SYMBOL_GPL(intel_vgpu_pdev);

void *intel_vgpu_opregion_va(struct intel_vgpu *vgpu)
{
	return vgpu_opregion(vgpu)->va;
}
EXPORT_SYMBOL_GPL(intel_vgpu_opregion_va);

struct intel_vgpu_port *intel_vgpu_port(struct intel_vgpu *vgpu, size_t port)
{
	return &(vgpu->display.ports[port]);
}
EXPORT_SYMBOL_GPL(intel_vgpu_port);

void *intel_vgpu_edid_block(struct intel_vgpu_port *port)
{
	return port->edid->edid_block;
}
EXPORT_SYMBOL_GPL(intel_vgpu_edid_block);

void intel_vgpu_set_handle(struct intel_vgpu *vgpu, unsigned long handle)
{
	vgpu->handle = handle;
}
EXPORT_SYMBOL_GPL(intel_vgpu_set_handle);

unsigned long intel_vgpu_handle(struct intel_vgpu *vgpu)
{
	return vgpu->handle;
}
EXPORT_SYMBOL_GPL(intel_vgpu_handle);

u32 *intel_vgpu_bar_ptr(struct intel_vgpu *vgpu, int bar)
{
	return (u32 *)(vgpu->cfg_space.virtual_cfg_space + bar);
}
EXPORT_SYMBOL_GPL(intel_vgpu_bar_ptr);

u64 intel_vgpu_get_bar_gpa(struct intel_vgpu *vgpu, int bar)
{
	/* We are 64bit bar. */
	return (*(u64 *)(vgpu->cfg_space.virtual_cfg_space + bar)) &
			PCI_BASE_ADDRESS_MEM_MASK;
}
EXPORT_SYMBOL_GPL(intel_vgpu_get_bar_gpa);

u64 intel_vgpu_get_bar_size(struct intel_vgpu *vgpu, int bar)
{
	return vgpu->cfg_space.bar[bar].size;
}
EXPORT_SYMBOL_GPL(intel_vgpu_get_bar_size);

u64 intel_gvt_cfg_space_size(struct intel_vgpu *vgpu)
{
	return vgpu->gvt->device_info.cfg_space_size;
}
EXPORT_SYMBOL_GPL(intel_gvt_cfg_space_size);

u64 intel_gvt_aperture_pa_base(struct intel_vgpu *vgpu)
{
	return gvt_aperture_pa_base(vgpu->gvt);
}
EXPORT_SYMBOL_GPL(intel_gvt_aperture_pa_base);

u64 intel_vgpu_aperture_offset(struct intel_vgpu *vgpu)
{
	return vgpu_aperture_offset(vgpu);
}
EXPORT_SYMBOL_GPL(intel_vgpu_aperture_offset);

u64 intel_vgpu_aperture_size(struct intel_vgpu *vgpu)
{
	return vgpu_aperture_sz(vgpu);
}
EXPORT_SYMBOL_GPL(intel_vgpu_aperture_size);

u64 intel_gvt_aperture_size(struct intel_vgpu *vgpu)
{
	return gvt_aperture_sz(vgpu->gvt);
}
EXPORT_SYMBOL_GPL(intel_gvt_aperture_size);

struct io_mapping *intel_gvt_gtt_iomap(struct intel_vgpu *vgpu)
{
	return &vgpu->gvt->dev_priv->ggtt.iomap;
}
EXPORT_SYMBOL_GPL(intel_gvt_gtt_iomap);

bool intel_gvt_in_gtt(struct intel_vgpu *vgpu, u64 offset)
{
	struct intel_gvt *gvt = vgpu->gvt;

	return (offset >= gvt->device_info.gtt_start_offset &&
		offset < gvt->device_info.gtt_start_offset + gvt_ggtt_sz(gvt));
}
EXPORT_SYMBOL_GPL(intel_gvt_in_gtt);

struct dentry *intel_vgpu_debugfs(struct intel_vgpu *vgpu)
{
	return vgpu->debugfs;
}
EXPORT_SYMBOL_GPL(intel_vgpu_debugfs);
