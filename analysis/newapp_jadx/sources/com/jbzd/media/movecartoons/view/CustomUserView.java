package com.jbzd.media.movecartoons.view;

import android.content.Context;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import com.jbzd.media.movecartoons.bean.response.ProfileBean;
import com.qnmd.adnnm.da0yzo.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\u0018\u00002\u00020\u0001B\u0017\u0012\u0006\u0010\u000f\u001a\u00020\u000e\u0012\u0006\u0010\u0011\u001a\u00020\u0010¢\u0006\u0004\b\u0012\u0010\u0013J\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006R\u0016\u0010\b\u001a\u00020\u00078\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\b\u0010\tR\u0016\u0010\u000b\u001a\u00020\n8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\u000b\u0010\fR\u0016\u0010\r\u001a\u00020\n8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\r\u0010\f¨\u0006\u0014"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/view/CustomUserView;", "Landroid/widget/LinearLayout;", "Lcom/jbzd/media/movecartoons/bean/response/ProfileBean;", "bean", "", "setUserInfo", "(Lcom/jbzd/media/movecartoons/bean/response/ProfileBean;)V", "Landroid/widget/TextView;", "userNameTextView", "Landroid/widget/TextView;", "Landroid/widget/ImageView;", "userImageView", "Landroid/widget/ImageView;", "userVipImageView", "Landroid/content/Context;", "context", "Landroid/util/AttributeSet;", "attrs", "<init>", "(Landroid/content/Context;Landroid/util/AttributeSet;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class CustomUserView extends LinearLayout {

    @NotNull
    private final ImageView userImageView;

    @NotNull
    private final TextView userNameTextView;

    @NotNull
    private final ImageView userVipImageView;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public CustomUserView(@NotNull Context context, @NotNull AttributeSet attrs) {
        super(context, attrs);
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(attrs, "attrs");
        LayoutInflater.from(context).inflate(R.layout.frag_profile, (ViewGroup) this, true);
        View findViewById = findViewById(R.id.iv_user_up);
        Intrinsics.checkNotNullExpressionValue(findViewById, "findViewById(R.id.iv_user_up)");
        this.userImageView = (ImageView) findViewById;
        View findViewById2 = findViewById(R.id.tv_postdetail_nickname);
        Intrinsics.checkNotNullExpressionValue(findViewById2, "findViewById(R.id.tv_postdetail_nickname)");
        this.userNameTextView = (TextView) findViewById2;
        View findViewById3 = findViewById(R.id.iv_user_vip);
        Intrinsics.checkNotNullExpressionValue(findViewById3, "findViewById(R.id.iv_user_vip)");
        this.userVipImageView = (ImageView) findViewById3;
    }

    public void _$_clearFindViewByIdCache() {
    }

    public final void setUserInfo(@NotNull ProfileBean bean) {
        Intrinsics.checkNotNullParameter(bean, "bean");
        this.userNameTextView.setText(bean.nickname);
        this.userVipImageView.setVisibility(Intrinsics.areEqual(bean.is_vip, "y") ? 0 : 8);
        this.userImageView.setVisibility(Intrinsics.areEqual(bean.is_up, "y") ? 0 : 8);
    }
}
