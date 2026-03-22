package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.widget.ClearEditText;

/* loaded from: classes2.dex */
public final class DialogTagsBinding implements ViewBinding {

    @NonNull
    public final View btnOutside;

    @NonNull
    public final ClearEditText cetNum;

    @NonNull
    public final RelativeLayout contentLayout;

    @NonNull
    public final TextView itvConfirmPost;

    @NonNull
    public final ImageView ivClose;

    @NonNull
    private final RelativeLayout rootView;

    @NonNull
    public final RecyclerView rvSelected;

    @NonNull
    public final RecyclerView rvTags;

    private DialogTagsBinding(@NonNull RelativeLayout relativeLayout, @NonNull View view, @NonNull ClearEditText clearEditText, @NonNull RelativeLayout relativeLayout2, @NonNull TextView textView, @NonNull ImageView imageView, @NonNull RecyclerView recyclerView, @NonNull RecyclerView recyclerView2) {
        this.rootView = relativeLayout;
        this.btnOutside = view;
        this.cetNum = clearEditText;
        this.contentLayout = relativeLayout2;
        this.itvConfirmPost = textView;
        this.ivClose = imageView;
        this.rvSelected = recyclerView;
        this.rvTags = recyclerView2;
    }

    @NonNull
    public static DialogTagsBinding bind(@NonNull View view) {
        int i2 = R.id.btn_outside;
        View findViewById = view.findViewById(R.id.btn_outside);
        if (findViewById != null) {
            i2 = R.id.cet_num;
            ClearEditText clearEditText = (ClearEditText) view.findViewById(R.id.cet_num);
            if (clearEditText != null) {
                i2 = R.id.content_layout;
                RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.content_layout);
                if (relativeLayout != null) {
                    i2 = R.id.itv_confirm_post;
                    TextView textView = (TextView) view.findViewById(R.id.itv_confirm_post);
                    if (textView != null) {
                        i2 = R.id.iv_close;
                        ImageView imageView = (ImageView) view.findViewById(R.id.iv_close);
                        if (imageView != null) {
                            i2 = R.id.rv_selected;
                            RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_selected);
                            if (recyclerView != null) {
                                i2 = R.id.rv_tags;
                                RecyclerView recyclerView2 = (RecyclerView) view.findViewById(R.id.rv_tags);
                                if (recyclerView2 != null) {
                                    return new DialogTagsBinding((RelativeLayout) view, findViewById, clearEditText, relativeLayout, textView, imageView, recyclerView, recyclerView2);
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static DialogTagsBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogTagsBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_tags, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public RelativeLayout getRoot() {
        return this.rootView;
    }
}
