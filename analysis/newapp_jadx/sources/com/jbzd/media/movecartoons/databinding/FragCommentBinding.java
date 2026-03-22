package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.RelativeLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.RecyclerView;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class FragCommentBinding implements ViewBinding {

    @NonNull
    public final DialogInputCommentBinding llBottomTool;

    @NonNull
    private final RelativeLayout rootView;

    @NonNull
    public final RecyclerView rvContent;

    @NonNull
    public final SwipeRefreshLayout swipeLayout;

    private FragCommentBinding(@NonNull RelativeLayout relativeLayout, @NonNull DialogInputCommentBinding dialogInputCommentBinding, @NonNull RecyclerView recyclerView, @NonNull SwipeRefreshLayout swipeRefreshLayout) {
        this.rootView = relativeLayout;
        this.llBottomTool = dialogInputCommentBinding;
        this.rvContent = recyclerView;
        this.swipeLayout = swipeRefreshLayout;
    }

    @NonNull
    public static FragCommentBinding bind(@NonNull View view) {
        int i2 = R.id.ll_bottom_tool;
        View findViewById = view.findViewById(R.id.ll_bottom_tool);
        if (findViewById != null) {
            DialogInputCommentBinding bind = DialogInputCommentBinding.bind(findViewById);
            RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_content);
            if (recyclerView != null) {
                SwipeRefreshLayout swipeRefreshLayout = (SwipeRefreshLayout) view.findViewById(R.id.swipeLayout);
                if (swipeRefreshLayout != null) {
                    return new FragCommentBinding((RelativeLayout) view, bind, recyclerView, swipeRefreshLayout);
                }
                i2 = R.id.swipeLayout;
            } else {
                i2 = R.id.rv_content;
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static FragCommentBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static FragCommentBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.frag_comment, viewGroup, false);
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
