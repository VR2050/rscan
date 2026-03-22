package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemSubCommentBinding implements ViewBinding {

    @NonNull
    public final TextView ivCenterPlayicon;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvContent;

    private ItemSubCommentBinding(@NonNull LinearLayout linearLayout, @NonNull TextView textView, @NonNull TextView textView2) {
        this.rootView = linearLayout;
        this.ivCenterPlayicon = textView;
        this.tvContent = textView2;
    }

    @NonNull
    public static ItemSubCommentBinding bind(@NonNull View view) {
        int i2 = R.id.iv_center_playicon;
        TextView textView = (TextView) view.findViewById(R.id.iv_center_playicon);
        if (textView != null) {
            i2 = R.id.tvContent;
            TextView textView2 = (TextView) view.findViewById(R.id.tvContent);
            if (textView2 != null) {
                return new ItemSubCommentBinding((LinearLayout) view, textView, textView2);
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemSubCommentBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemSubCommentBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_sub_comment, viewGroup, false);
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
