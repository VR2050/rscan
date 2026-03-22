package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.image.CircleImageView;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class HomeLongVideoBottomUserBinding implements ViewBinding {

    @NonNull
    public final CircleImageView civHead;

    @NonNull
    public final ImageTextView itvClicks;

    @NonNull
    public final ImageTextView itvLove;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvPostdetailNickname;

    private HomeLongVideoBottomUserBinding(@NonNull LinearLayout linearLayout, @NonNull CircleImageView circleImageView, @NonNull ImageTextView imageTextView, @NonNull ImageTextView imageTextView2, @NonNull TextView textView) {
        this.rootView = linearLayout;
        this.civHead = circleImageView;
        this.itvClicks = imageTextView;
        this.itvLove = imageTextView2;
        this.tvPostdetailNickname = textView;
    }

    @NonNull
    public static HomeLongVideoBottomUserBinding bind(@NonNull View view) {
        int i2 = R.id.civ_head;
        CircleImageView circleImageView = (CircleImageView) view.findViewById(R.id.civ_head);
        if (circleImageView != null) {
            i2 = R.id.itv_clicks;
            ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.itv_clicks);
            if (imageTextView != null) {
                i2 = R.id.itv_love;
                ImageTextView imageTextView2 = (ImageTextView) view.findViewById(R.id.itv_love);
                if (imageTextView2 != null) {
                    i2 = R.id.tv_postdetail_nickname;
                    TextView textView = (TextView) view.findViewById(R.id.tv_postdetail_nickname);
                    if (textView != null) {
                        return new HomeLongVideoBottomUserBinding((LinearLayout) view, circleImageView, imageTextView, imageTextView2, textView);
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static HomeLongVideoBottomUserBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static HomeLongVideoBottomUserBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.home_long_video_bottom_user, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public LinearLayout getRoot() {
        return this.rootView;
    }
}
