package com.jbzd.media.movecartoons.view.video;

import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.qnmd.adnnm.da0yzo.R;
import java.util.ArrayList;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u0007\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\u0018\u00002\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00030\u0001B\u001f\u0012\u0016\u0010\u0014\u001a\u0012\u0012\u0004\u0012\u00020\u00020\u0012j\b\u0012\u0004\u0012\u00020\u0002`\u0013¢\u0006\u0004\b\u0015\u0010\u0016J\u001f\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0004\u001a\u00020\u00032\u0006\u0010\u0005\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\u000b\u001a\u00020\u00062\u0006\u0010\n\u001a\u00020\t¢\u0006\u0004\b\u000b\u0010\fR\"\u0010\r\u001a\u00020\t8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\r\u0010\u000e\u001a\u0004\b\u000f\u0010\u0010\"\u0004\b\u0011\u0010\f¨\u0006\u0017"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/view/video/SpeedAdapter;", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "Lcom/jbzd/media/movecartoons/view/video/Speed;", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "item", "", "convert", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/view/video/Speed;)V", "", "speed", "setSpeed", "(F)V", "default", "F", "getDefault", "()F", "setDefault", "Ljava/util/ArrayList;", "Lkotlin/collections/ArrayList;", "speeds", "<init>", "(Ljava/util/ArrayList;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class SpeedAdapter extends BaseQuickAdapter<Speed, BaseViewHolder> {
    private float default;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public SpeedAdapter(@NotNull ArrayList<Speed> speeds) {
        super(R.layout.item_speed_tv, speeds);
        Intrinsics.checkNotNullParameter(speeds, "speeds");
        this.default = 1.0f;
    }

    public final float getDefault() {
        return this.default;
    }

    public final void setDefault(float f2) {
        this.default = f2;
    }

    public final void setSpeed(float speed) {
        this.default = speed;
        notifyDataSetChanged();
    }

    @Override // com.chad.library.adapter.base.BaseQuickAdapter
    public void convert(@NotNull BaseViewHolder helper, @NotNull Speed item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        helper.m3919i(R.id.f13004tv, item.getName());
        helper.itemView.setSelected(item.getSpeed() == getDefault());
    }
}
