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
import com.qnmd.adnnm.da0yzo.R;
import io.github.armcha.autolink.AutoLinkTextView;

/* loaded from: classes2.dex */
public final class ItemMsglistContinueBinding implements ViewBinding {

    @NonNull
    public final CircleImageView civHead;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final AutoLinkTextView tvContentPre;

    @NonNull
    public final TextView tvName;

    @NonNull
    public final TextView tvTime;

    private ItemMsglistContinueBinding(@NonNull LinearLayout linearLayout, @NonNull CircleImageView circleImageView, @NonNull AutoLinkTextView autoLinkTextView, @NonNull TextView textView, @NonNull TextView textView2) {
        this.rootView = linearLayout;
        this.civHead = circleImageView;
        this.tvContentPre = autoLinkTextView;
        this.tvName = textView;
        this.tvTime = textView2;
    }

    @NonNull
    public static ItemMsglistContinueBinding bind(@NonNull View view) {
        int i2 = R.id.civ_head;
        CircleImageView circleImageView = (CircleImageView) view.findViewById(R.id.civ_head);
        if (circleImageView != null) {
            i2 = R.id.tv_contentPre;
            AutoLinkTextView autoLinkTextView = (AutoLinkTextView) view.findViewById(R.id.tv_contentPre);
            if (autoLinkTextView != null) {
                i2 = R.id.tv_name;
                TextView textView = (TextView) view.findViewById(R.id.tv_name);
                if (textView != null) {
                    i2 = R.id.tv_time;
                    TextView textView2 = (TextView) view.findViewById(R.id.tv_time);
                    if (textView2 != null) {
                        return new ItemMsglistContinueBinding((LinearLayout) view, circleImageView, autoLinkTextView, textView, textView2);
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemMsglistContinueBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemMsglistContinueBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_msglist_continue, viewGroup, false);
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
