package im.uwrkaxlmjj.ui.hui.visualcall;

import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.widget.CompoundButton;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.appcompat.widget.SwitchCompat;
import androidx.recyclerview.widget.RecyclerView;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class ChartUserAdapter extends BaseRecyclerViewAdapter<ChartViewHolder> {
    private List<String> mList = new ArrayList();
    private Map<String, ChartUserBean> mMap = new LinkedHashMap();
    private OnSubConfigChangeListener mOnSubConfigChangeListener;

    public interface OnSubConfigChangeListener {
        void onFlipView(String str, int i, boolean z);

        void onShowVideoInfo(String str, int i);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public ChartViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
        View rootView = LayoutInflater.from(parent.getContext()).inflate(R.layout.chart_content_userlist_item, parent, false);
        return new ChartViewHolder(rootView);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public void onBindViewHolder(ChartViewHolder holder, int position) {
        holder.mScreenLayout.setVisibility(8);
        holder.mVideoLayout.setVisibility(8);
        if (this.mList.isEmpty()) {
            return;
        }
        final ChartUserBean item = this.mMap.get(this.mList.get(position));
        holder.mSurfaceContainer.removeAllViews();
        holder.mScreenSurfaceContainer.removeAllViews();
        if (item == null) {
            return;
        }
        if (item.mCameraSurface != null) {
            holder.mVideoLayout.setVisibility(0);
            ViewParent parent = item.mCameraSurface.getParent();
            if (parent != null) {
                if (parent instanceof FrameLayout) {
                    ((FrameLayout) parent).removeAllViews();
                }
                holder.mSurfaceContainer.removeAllViews();
            }
            holder.mSurfaceContainer.addView(item.mCameraSurface, new FrameLayout.LayoutParams(-1, -1));
        }
        if (item.mScreenSurface != null) {
            holder.mScreenLayout.setVisibility(0);
            ViewParent parent2 = item.mScreenSurface.getParent();
            if (parent2 != null) {
                if (parent2 instanceof FrameLayout) {
                    ((FrameLayout) parent2).removeAllViews();
                }
                holder.mScreenSurfaceContainer.removeAllViews();
            }
            holder.mScreenSurfaceContainer.addView(item.mScreenSurface, new FrameLayout.LayoutParams(-1, -1));
        }
        holder.mVideoFlip.setOnCheckedChangeListener(null);
        holder.mVideoFlip.setChecked(item.mIsCameraFlip);
        holder.mScreenFlip.setOnCheckedChangeListener(null);
        holder.mScreenFlip.setChecked(item.mIsScreenFlip);
        holder.mVideoFlip.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$ChartUserAdapter$wbFLN0yXZsck4IyqgBUFrikhXBI
            @Override // android.widget.CompoundButton.OnCheckedChangeListener
            public final void onCheckedChanged(CompoundButton compoundButton, boolean z) {
                this.f$0.lambda$onBindViewHolder$0$ChartUserAdapter(item, compoundButton, z);
            }
        });
        holder.mScreenFlip.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$ChartUserAdapter$FWCl83LeQycN3d-p8SHO_JBLqJE
            @Override // android.widget.CompoundButton.OnCheckedChangeListener
            public final void onCheckedChanged(CompoundButton compoundButton, boolean z) {
                this.f$0.lambda$onBindViewHolder$1$ChartUserAdapter(item, compoundButton, z);
            }
        });
        holder.mVideoMediaInfo.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$ChartUserAdapter$BB7HMReZhimGRLVbsuMy6Ueo7EQ
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$onBindViewHolder$2$ChartUserAdapter(item, view);
            }
        });
        holder.mScreenMediaInfo.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$ChartUserAdapter$SEV6ehluYTDzLdVz0PvJZfCIV7Q
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$onBindViewHolder$3$ChartUserAdapter(item, view);
            }
        });
    }

    public /* synthetic */ void lambda$onBindViewHolder$0$ChartUserAdapter(ChartUserBean item, CompoundButton buttonView, boolean isChecked) {
        OnSubConfigChangeListener onSubConfigChangeListener = this.mOnSubConfigChangeListener;
        if (onSubConfigChangeListener != null) {
            onSubConfigChangeListener.onFlipView(item.mUserId, 1001, isChecked);
        }
    }

    public /* synthetic */ void lambda$onBindViewHolder$1$ChartUserAdapter(ChartUserBean item, CompoundButton buttonView, boolean isChecked) {
        OnSubConfigChangeListener onSubConfigChangeListener = this.mOnSubConfigChangeListener;
        if (onSubConfigChangeListener != null) {
            onSubConfigChangeListener.onFlipView(item.mUserId, 1002, isChecked);
        }
    }

    public /* synthetic */ void lambda$onBindViewHolder$2$ChartUserAdapter(ChartUserBean item, View v) {
        OnSubConfigChangeListener onSubConfigChangeListener = this.mOnSubConfigChangeListener;
        if (onSubConfigChangeListener != null) {
            onSubConfigChangeListener.onShowVideoInfo(item.mUserId, 1001);
        }
    }

    public /* synthetic */ void lambda$onBindViewHolder$3$ChartUserAdapter(ChartUserBean item, View v) {
        OnSubConfigChangeListener onSubConfigChangeListener = this.mOnSubConfigChangeListener;
        if (onSubConfigChangeListener != null) {
            onSubConfigChangeListener.onShowVideoInfo(item.mUserId, 1002);
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemCount() {
        return this.mList.size();
    }

    public void setData(List<ChartUserBean> list, boolean notify) {
        this.mList.clear();
        this.mMap.clear();
        for (ChartUserBean item : list) {
            this.mList.add(item.mUserId);
            this.mMap.put(item.mUserId, item);
        }
        if (notify) {
            notifyDataSetChanged();
        }
    }

    public void addData(ChartUserBean data, boolean notify) {
        this.mList.add(data.mUserId);
        this.mMap.put(data.mUserId, data);
        if (notify) {
            notifyItemInserted(this.mList.size() - 1);
        }
    }

    public void removeData(String uid, boolean notify) {
        int index = this.mList.indexOf(uid);
        if (index < 0) {
            return;
        }
        this.mList.remove(uid);
        this.mMap.remove(uid);
        if (notify) {
            notifyItemRemoved(index);
        }
    }

    public void updateData(ChartUserBean data, boolean notify) {
        if (this.mList.contains(data.mUserId)) {
            int index = this.mList.indexOf(data.mUserId);
            this.mMap.put(data.mUserId, data);
            if (notify) {
                notifyItemChanged(index);
                return;
            }
            return;
        }
        addData(data, notify);
    }

    public ChartUserBean createDataIfNull(String uid) {
        ChartUserBean ret;
        return (TextUtils.isEmpty(uid) || (ret = this.mMap.get(uid)) == null) ? new ChartUserBean() : ret;
    }

    public boolean containsUser(String uid) {
        if (!this.mList.isEmpty() && this.mList.contains(uid)) {
            return true;
        }
        return false;
    }

    public static class ChartViewHolder extends RecyclerView.ViewHolder {
        public SwitchCompat mScreenFlip;
        public LinearLayout mScreenLayout;
        public TextView mScreenMediaInfo;
        public FrameLayout mScreenSurfaceContainer;
        public FrameLayout mSurfaceContainer;
        public SwitchCompat mVideoFlip;
        public LinearLayout mVideoLayout;
        public TextView mVideoMediaInfo;

        public ChartViewHolder(View itemView) {
            super(itemView);
            this.mVideoLayout = (LinearLayout) itemView.findViewById(R.attr.chart_content_userlist_item_video_layout);
            this.mSurfaceContainer = (FrameLayout) itemView.findViewById(R.attr.chart_content_userlist_item_surface_container);
            this.mScreenLayout = (LinearLayout) itemView.findViewById(R.attr.chart_content_userlist_item_screen_layout);
            this.mScreenSurfaceContainer = (FrameLayout) itemView.findViewById(R.attr.chart_content_userlist_item2_surface_container);
            this.mVideoFlip = (SwitchCompat) itemView.findViewById(R.attr.chart_userlist_item_video_flip);
            this.mVideoMediaInfo = (TextView) itemView.findViewById(R.attr.chart_userlist_item_show_video_media_info);
            this.mScreenFlip = (SwitchCompat) itemView.findViewById(R.attr.chart_userlist_item_screen_flip);
            this.mScreenMediaInfo = (TextView) itemView.findViewById(R.attr.chart_userlist_item_show_screen_media_info);
        }
    }

    public void setOnSubConfigChangeListener(OnSubConfigChangeListener l) {
        this.mOnSubConfigChangeListener = l;
    }
}
