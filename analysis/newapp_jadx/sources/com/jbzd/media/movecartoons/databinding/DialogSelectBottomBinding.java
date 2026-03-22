package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class DialogSelectBottomBinding implements ViewBinding {

    @NonNull
    public final TextView btnCancel;

    @NonNull
    public final FrameLayout flBg;

    @NonNull
    public final FrameLayout flRoot;

    @NonNull
    public final View outsideView;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final RecyclerView rvContent;

    private DialogSelectBottomBinding(@NonNull LinearLayout linearLayout, @NonNull TextView textView, @NonNull FrameLayout frameLayout, @NonNull FrameLayout frameLayout2, @NonNull View view, @NonNull RecyclerView recyclerView) {
        this.rootView = linearLayout;
        this.btnCancel = textView;
        this.flBg = frameLayout;
        this.flRoot = frameLayout2;
        this.outsideView = view;
        this.rvContent = recyclerView;
    }

    @NonNull
    public static DialogSelectBottomBinding bind(@NonNull View view) {
        int i2 = R.id.btnCancel;
        TextView textView = (TextView) view.findViewById(R.id.btnCancel);
        if (textView != null) {
            i2 = R.id.flBg;
            FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.flBg);
            if (frameLayout != null) {
                i2 = R.id.flRoot;
                FrameLayout frameLayout2 = (FrameLayout) view.findViewById(R.id.flRoot);
                if (frameLayout2 != null) {
                    i2 = R.id.outside_view;
                    View findViewById = view.findViewById(R.id.outside_view);
                    if (findViewById != null) {
                        i2 = R.id.rv_content;
                        RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_content);
                        if (recyclerView != null) {
                            return new DialogSelectBottomBinding((LinearLayout) view, textView, frameLayout, frameLayout2, findViewById, recyclerView);
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static DialogSelectBottomBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogSelectBottomBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_select_bottom, viewGroup, false);
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
