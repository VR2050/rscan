package com.jbzd.media.movecartoons.p396ui.index.medialib.child;

import android.content.Context;
import android.graphics.Color;
import androidx.core.content.ContextCompat;
import com.jbzd.media.movecartoons.databinding.ActPromotionDataBinding;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseBindingActivity;
import com.qunidayede.supportlibrary.databinding.TitleBarLayoutBinding;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p131d.p132a.p133a.C1499a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000$\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0007\u0018\u0000 \u000f2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001\u000fB\u0007¢\u0006\u0004\b\u000e\u0010\u0005J\u000f\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0004\u0010\u0005J\u000f\u0010\u0007\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\n\u001a\u00020\tH\u0016¢\u0006\u0004\b\n\u0010\u000bJ\u000f\u0010\f\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\f\u0010\bJ\u000f\u0010\r\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\r\u0010\u0005¨\u0006\u0010"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/medialib/child/PromotionDataActivity;", "Lcom/qunidayede/supportlibrary/core/view/BaseBindingActivity;", "Lcom/jbzd/media/movecartoons/databinding/ActPromotionDataBinding;", "", "initView", "()V", "", "getTopBarTitle", "()Ljava/lang/String;", "", "backColor", "()I", "getRightTitle", "clickRight", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class PromotionDataActivity extends BaseBindingActivity<ActPromotionDataBinding> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006¨\u0006\t"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/medialib/child/PromotionDataActivity$Companion;", "", "Landroid/content/Context;", "context", "", "start", "(Landroid/content/Context;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final void start(@NotNull Context context) {
            C1499a.m602X(context, "context", context, PromotionDataActivity.class);
        }
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public int backColor() {
        return R.color.white;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public void clickRight() {
        IncomeLogActivity.INSTANCE.start(this);
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    @NotNull
    public String getRightTitle() {
        String string = getString(R.string.promotion_benefit);
        Intrinsics.checkNotNullExpressionValue(string, "getString(R.string.promotion_benefit)");
        return string;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    @NotNull
    public String getTopBarTitle() {
        String string = getString(R.string.promotion_data);
        Intrinsics.checkNotNullExpressionValue(string, "getString(R.string.promotion_data)");
        return string;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public void initView() {
        titleBinding(new Function1<TitleBarLayoutBinding, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.medialib.child.PromotionDataActivity$initView$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TitleBarLayoutBinding titleBarLayoutBinding) {
                invoke2(titleBarLayoutBinding);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull TitleBarLayoutBinding titleBinding) {
                Intrinsics.checkNotNullParameter(titleBinding, "$this$titleBinding");
                titleBinding.tvTitle.setTextColor(ContextCompat.getColor(PromotionDataActivity.this, R.color.white));
                titleBinding.getRoot().setBackgroundColor(Color.parseColor("#151618"));
            }
        });
    }
}
