package com.jbzd.media.movecartoons.p396ui.settings;

import androidx.lifecycle.MutableLiveData;
import androidx.lifecycle.Observer;
import com.jbzd.media.movecartoons.p396ui.mine.MineViewModel;
import com.jbzd.media.movecartoons.p396ui.settings.MineInfoActivity;
import com.jbzd.media.movecartoons.p396ui.settings.MineInfoActivity$initView$2;
import com.qnmd.adnnm.da0yzo.R;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\u0010\u0002\u001a\u00020\u0001*\u00020\u0000H\n¢\u0006\u0004\b\u0002\u0010\u0003"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/mine/MineViewModel;", "", "<anonymous>", "(Lcom/jbzd/media/movecartoons/ui/mine/MineViewModel;)V"}, m5312k = 3, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class MineInfoActivity$initView$2 extends Lambda implements Function1<MineViewModel, Unit> {
    public final /* synthetic */ MineInfoActivity this$0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public MineInfoActivity$initView$2(MineInfoActivity mineInfoActivity) {
        super(1);
        this.this$0 = mineInfoActivity;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: invoke$lambda-0, reason: not valid java name */
    public static final void m5999invoke$lambda0(MineInfoActivity this$0, Boolean it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullExpressionValue(it, "it");
        if (it.booleanValue()) {
            C2354n.m2409L1(this$0.getString(R.string.save_sccuess));
            MineViewModel.INSTANCE.getUserInfo();
            this$0.finish();
        }
    }

    @Override // kotlin.jvm.functions.Function1
    public /* bridge */ /* synthetic */ Unit invoke(MineViewModel mineViewModel) {
        invoke2(mineViewModel);
        return Unit.INSTANCE;
    }

    /* renamed from: invoke, reason: avoid collision after fix types in other method */
    public final void invoke2(@NotNull MineViewModel viewModels) {
        Intrinsics.checkNotNullParameter(viewModels, "$this$viewModels");
        MutableLiveData<Boolean> userInfoUpdateSuccess = viewModels.getUserInfoUpdateSuccess();
        final MineInfoActivity mineInfoActivity = this.this$0;
        userInfoUpdateSuccess.observe(mineInfoActivity, new Observer() { // from class: b.a.a.a.t.n.d
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                MineInfoActivity$initView$2.m5999invoke$lambda0(MineInfoActivity.this, (Boolean) obj);
            }
        });
    }
}
