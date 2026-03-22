package com.jbzd.media.movecartoons.p396ui.welfare;

import android.graphics.drawable.Drawable;
import androidx.annotation.RequiresApi;
import androidx.core.content.ContextCompat;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.response.WelfareBean;
import com.noober.background.drawable.DrawableCreator;
import com.noober.background.view.BLTextView;
import com.qnmd.adnnm.da0yzo.R;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.LazyThreadSafetyMode;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000$\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\f\u0018\u00002\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00030\u0001B\u0007¢\u0006\u0004\b\u0013\u0010\u0014J\u001f\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0004\u001a\u00020\u00032\u0006\u0010\u0005\u001a\u00020\u0002H\u0015¢\u0006\u0004\b\u0007\u0010\bR%\u0010\u000f\u001a\n \n*\u0004\u0018\u00010\t0\t8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u000b\u0010\f\u001a\u0004\b\r\u0010\u000eR%\u0010\u0012\u001a\n \n*\u0004\u0018\u00010\t0\t8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0010\u0010\f\u001a\u0004\b\u0011\u0010\u000e¨\u0006\u0015"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/welfare/WelfareTaskAdapter;", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "Lcom/jbzd/media/movecartoons/bean/response/WelfareBean$TaskItem;", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "holder", "item", "", "convert", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/WelfareBean$TaskItem;)V", "Landroid/graphics/drawable/Drawable;", "kotlin.jvm.PlatformType", "color3$delegate", "Lkotlin/Lazy;", "getColor3", "()Landroid/graphics/drawable/Drawable;", "color3", "color1$delegate", "getColor1", "color1", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class WelfareTaskAdapter extends BaseQuickAdapter<WelfareBean.TaskItem, BaseViewHolder> {

    /* renamed from: color1$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy color1;

    /* renamed from: color3$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy color3;

    public WelfareTaskAdapter() {
        super(R.layout.todo_task_item, null, 2, null);
        LazyThreadSafetyMode lazyThreadSafetyMode = LazyThreadSafetyMode.NONE;
        this.color1 = LazyKt__LazyJVMKt.lazy(lazyThreadSafetyMode, (Function0) new Function0<Drawable>() { // from class: com.jbzd.media.movecartoons.ui.welfare.WelfareTaskAdapter$color1$2
            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final Drawable invoke() {
                return new DrawableCreator.Builder().setCornersRadius(C2354n.m2442W1(20.0f)).setSolidColor(C2354n.m2383D(R.color.color_250_217_163)).build();
            }
        });
        this.color3 = LazyKt__LazyJVMKt.lazy(lazyThreadSafetyMode, (Function0) new Function0<Drawable>() { // from class: com.jbzd.media.movecartoons.ui.welfare.WelfareTaskAdapter$color3$2
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

    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue
    java.lang.NullPointerException: Cannot invoke "java.util.List.iterator()" because the return value of "jadx.core.dex.visitors.regions.SwitchOverStringVisitor$SwitchData.getNewCases()" is null
    	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.restoreSwitchOverString(SwitchOverStringVisitor.java:109)
    	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.visitRegion(SwitchOverStringVisitor.java:66)
    	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:77)
    	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:82)
     */
    @Override // com.chad.library.adapter.base.BaseQuickAdapter
    @RequiresApi(23)
    public void convert(@NotNull BaseViewHolder holder, @NotNull WelfareBean.TaskItem item) {
        Intrinsics.checkNotNullParameter(holder, "holder");
        Intrinsics.checkNotNullParameter(item, "item");
        holder.m3919i(R.id.tv_task_title, item.name);
        holder.m3919i(R.id.tv_task_title_hint, item.description);
        String str = item.type;
        if (str != null) {
            switch (str.hashCode()) {
                case 103149417:
                    if (str.equals("login")) {
                        holder.m3917g(R.id.iv_task_icon, R.drawable.ic_task_login);
                        break;
                    }
                    break;
                case 109400031:
                    if (str.equals("share")) {
                        holder.m3917g(R.id.iv_task_icon, R.drawable.ic_task_share);
                        break;
                    }
                    break;
                case 950398559:
                    if (str.equals("comment")) {
                        holder.m3917g(R.id.iv_task_icon, R.drawable.ic_task_comment);
                        break;
                    }
                    break;
                case 1427818632:
                    if (str.equals("download")) {
                        holder.m3917g(R.id.iv_task_icon, R.drawable.ic_task_download);
                        break;
                    }
                    break;
            }
        }
        BLTextView bLTextView = (BLTextView) holder.m3912b(R.id.tv_task_action_state);
        bLTextView.setText(item.status_text);
        String str2 = item.status;
        if (str2 != null) {
            switch (str2.hashCode()) {
                case 48:
                    if (str2.equals("0")) {
                        bLTextView.setBackground(ContextCompat.getDrawable(getContext(), R.drawable.btn_orangehalf_style));
                        break;
                    }
                    break;
                case 49:
                    if (str2.equals("1")) {
                        bLTextView.setBackground(ContextCompat.getDrawable(getContext(), R.drawable.btn_orangenew_style));
                        break;
                    }
                    break;
                case 50:
                    if (str2.equals("2")) {
                        bLTextView.setBackground(ContextCompat.getDrawable(getContext(), R.drawable.bg_task_done));
                        break;
                    }
                    break;
            }
        }
    }
}
