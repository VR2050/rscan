package com.jbzd.media.movecartoons.p396ui.settings;

import android.widget.CompoundButton;
import android.widget.TextView;
import com.jbzd.media.movecartoons.databinding.ActivityPersonalInfoBinding;
import com.jbzd.media.movecartoons.p396ui.settings.MineInfoActivity$initView$1;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\u0010\u0002\u001a\u00020\u0001*\u00020\u0000H\n¢\u0006\u0004\b\u0002\u0010\u0003"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/databinding/ActivityPersonalInfoBinding;", "", "<anonymous>", "(Lcom/jbzd/media/movecartoons/databinding/ActivityPersonalInfoBinding;)V"}, m5312k = 3, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class MineInfoActivity$initView$1 extends Lambda implements Function1<ActivityPersonalInfoBinding, Unit> {
    public final /* synthetic */ MineInfoActivity this$0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public MineInfoActivity$initView$1(MineInfoActivity mineInfoActivity) {
        super(1);
        this.this$0 = mineInfoActivity;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: invoke$lambda-0, reason: not valid java name */
    public static final void m5997invoke$lambda0(ActivityPersonalInfoBinding this_bodyBinding, CompoundButton compoundButton, boolean z) {
        Intrinsics.checkNotNullParameter(this_bodyBinding, "$this_bodyBinding");
        if (z && this_bodyBinding.radioSexMale.isChecked()) {
            this_bodyBinding.radioSexMale.setChecked(false);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: invoke$lambda-1, reason: not valid java name */
    public static final void m5998invoke$lambda1(ActivityPersonalInfoBinding this_bodyBinding, CompoundButton compoundButton, boolean z) {
        Intrinsics.checkNotNullParameter(this_bodyBinding, "$this_bodyBinding");
        if (z && this_bodyBinding.radioSexFemale.isChecked()) {
            this_bodyBinding.radioSexFemale.setChecked(false);
        }
    }

    @Override // kotlin.jvm.functions.Function1
    public /* bridge */ /* synthetic */ Unit invoke(ActivityPersonalInfoBinding activityPersonalInfoBinding) {
        invoke2(activityPersonalInfoBinding);
        return Unit.INSTANCE;
    }

    /* renamed from: invoke, reason: avoid collision after fix types in other method */
    public final void invoke2(@NotNull final ActivityPersonalInfoBinding bodyBinding) {
        Intrinsics.checkNotNullParameter(bodyBinding, "$this$bodyBinding");
        bodyBinding.radioSexFemale.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() { // from class: b.a.a.a.t.n.c
            @Override // android.widget.CompoundButton.OnCheckedChangeListener
            public final void onCheckedChanged(CompoundButton compoundButton, boolean z) {
                MineInfoActivity$initView$1.m5997invoke$lambda0(ActivityPersonalInfoBinding.this, compoundButton, z);
            }
        });
        bodyBinding.radioSexMale.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() { // from class: b.a.a.a.t.n.b
            @Override // android.widget.CompoundButton.OnCheckedChangeListener
            public final void onCheckedChanged(CompoundButton compoundButton, boolean z) {
                MineInfoActivity$initView$1.m5998invoke$lambda1(ActivityPersonalInfoBinding.this, compoundButton, z);
            }
        });
        TextView textView = bodyBinding.btnSubmit;
        final MineInfoActivity mineInfoActivity = this.this$0;
        C2354n.m2374A(textView, 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.settings.MineInfoActivity$initView$1.3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView2) {
                invoke2(textView2);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull TextView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                MineInfoActivity.this.updateUserInfo();
            }
        }, 1);
    }
}
