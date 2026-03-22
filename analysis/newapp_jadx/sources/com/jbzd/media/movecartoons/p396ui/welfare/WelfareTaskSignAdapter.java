package com.jbzd.media.movecartoons.p396ui.welfare;

import android.graphics.drawable.Drawable;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.response.WelfareBean;
import com.noober.background.drawable.DrawableCreator;
import com.qnmd.adnnm.da0yzo.R;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.LazyThreadSafetyMode;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000$\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\f\u0018\u00002\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00030\u0001B\u0007¢\u0006\u0004\b\u0013\u0010\u0014J\u001f\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0004\u001a\u00020\u00032\u0006\u0010\u0005\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\u0007\u0010\bR%\u0010\u000f\u001a\n \n*\u0004\u0018\u00010\t0\t8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u000b\u0010\f\u001a\u0004\b\r\u0010\u000eR%\u0010\u0012\u001a\n \n*\u0004\u0018\u00010\t0\t8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0010\u0010\f\u001a\u0004\b\u0011\u0010\u000e¨\u0006\u0015"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/welfare/WelfareTaskSignAdapter;", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "Lcom/jbzd/media/movecartoons/bean/response/WelfareBean$SignItem;", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "holder", "item", "", "convert", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/WelfareBean$SignItem;)V", "Landroid/graphics/drawable/Drawable;", "kotlin.jvm.PlatformType", "color1$delegate", "Lkotlin/Lazy;", "getColor1", "()Landroid/graphics/drawable/Drawable;", "color1", "color3$delegate", "getColor3", "color3", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class WelfareTaskSignAdapter extends BaseQuickAdapter<WelfareBean.SignItem, BaseViewHolder> {

    /* renamed from: color1$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy color1;

    /* renamed from: color3$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy color3;

    public WelfareTaskSignAdapter() {
        super(R.layout.item_sign, null, 2, null);
        LazyThreadSafetyMode lazyThreadSafetyMode = LazyThreadSafetyMode.NONE;
        this.color1 = LazyKt__LazyJVMKt.lazy(lazyThreadSafetyMode, (Function0) new Function0<Drawable>() { // from class: com.jbzd.media.movecartoons.ui.welfare.WelfareTaskSignAdapter$color1$2
            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final Drawable invoke() {
                return new DrawableCreator.Builder().setCornersRadius(C2354n.m2442W1(20.0f)).setSolidColor(C2354n.m2383D(R.color.color_250_217_163)).build();
            }
        });
        this.color3 = LazyKt__LazyJVMKt.lazy(lazyThreadSafetyMode, (Function0) new Function0<Drawable>() { // from class: com.jbzd.media.movecartoons.ui.welfare.WelfareTaskSignAdapter$color3$2
            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final Drawable invoke() {
                return new DrawableCreator.Builder().setCornersRadius(C2354n.m2442W1(20.0f)).setSolidColor(C2354n.m2383D(R.color.color_149_149_149)).build();
            }
        });
        addChildClickViewIds(R.id.tv_task_action_state);
    }

    private final Drawable getColor1() {
        return (Drawable) this.color1.getValue();
    }

    private final Drawable getColor3() {
        return (Drawable) this.color3.getValue();
    }

    @Override // com.chad.library.adapter.base.BaseQuickAdapter
    public void convert(@NotNull BaseViewHolder holder, @NotNull WelfareBean.SignItem item) {
        Intrinsics.checkNotNullParameter(holder, "holder");
        Intrinsics.checkNotNullParameter(item, "item");
        String str = item.has_done;
        holder.m3919i(R.id.tv_signname_day, item.name);
        holder.m3919i(R.id.tv_signnum_day, str.equals("y") ? "已领取" : Intrinsics.stringPlus(item.num, "积分"));
        ((ConstraintLayout) holder.m3912b(R.id.ll_signitem_root)).setSelected(str.equals("y"));
    }
}
