package com.luck.picture.lib.adapter;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;
import com.luck.picture.lib.C3979R;
import com.luck.picture.lib.adapter.PictureWeChatPreviewGalleryAdapter;
import com.luck.picture.lib.config.PictureMimeType;
import com.luck.picture.lib.config.PictureSelectionConfig;
import com.luck.picture.lib.engine.ImageEngine;
import com.luck.picture.lib.entity.LocalMedia;
import com.luck.picture.lib.style.PictureSelectorUIStyle;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public class PictureWeChatPreviewGalleryAdapter extends RecyclerView.Adapter<ViewHolder> {
    private PictureSelectionConfig config;
    private List<LocalMedia> list;
    private OnItemClickListener listener;

    public interface OnItemClickListener {
        void onItemClick(int i2, LocalMedia localMedia, View view);
    }

    public static class ViewHolder extends RecyclerView.ViewHolder {
        public ImageView ivImage;
        public ImageView ivPlay;
        public View viewBorder;

        public ViewHolder(View view) {
            super(view);
            this.ivImage = (ImageView) view.findViewById(C3979R.id.ivImage);
            this.ivPlay = (ImageView) view.findViewById(C3979R.id.ivPlay);
            View findViewById = view.findViewById(C3979R.id.viewBorder);
            this.viewBorder = findViewById;
            PictureSelectorUIStyle pictureSelectorUIStyle = PictureSelectionConfig.uiStyle;
            if (pictureSelectorUIStyle != null) {
                findViewById.setBackgroundResource(pictureSelectorUIStyle.picture_bottom_gallery_frameBackground);
            }
        }
    }

    public PictureWeChatPreviewGalleryAdapter(PictureSelectionConfig pictureSelectionConfig) {
        this.config = pictureSelectionConfig;
    }

    /* renamed from: a */
    public /* synthetic */ void m4540a(ViewHolder viewHolder, int i2, View view) {
        if (this.listener == null || viewHolder.getAdapterPosition() < 0) {
            return;
        }
        this.listener.onItemClick(viewHolder.getAdapterPosition(), getItem(i2), view);
    }

    public void addSingleMediaToData(LocalMedia localMedia) {
        List<LocalMedia> list = this.list;
        if (list != null) {
            list.clear();
            this.list.add(localMedia);
            notifyDataSetChanged();
        }
    }

    public LocalMedia getItem(int i2) {
        List<LocalMedia> list = this.list;
        if (list == null || list.size() <= 0) {
            return null;
        }
        return this.list.get(i2);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemCount() {
        List<LocalMedia> list = this.list;
        if (list != null) {
            return list.size();
        }
        return 0;
    }

    public boolean isDataEmpty() {
        List<LocalMedia> list = this.list;
        return list == null || list.size() == 0;
    }

    public void removeMediaToData(LocalMedia localMedia) {
        List<LocalMedia> list = this.list;
        if (list == null || list.size() <= 0) {
            return;
        }
        this.list.remove(localMedia);
        notifyDataSetChanged();
    }

    public void setItemClickListener(OnItemClickListener onItemClickListener) {
        this.listener = onItemClickListener;
    }

    public void setNewData(List<LocalMedia> list) {
        if (list == null) {
            list = new ArrayList<>();
        }
        this.list = list;
        notifyDataSetChanged();
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public void onBindViewHolder(@NonNull final ViewHolder viewHolder, final int i2) {
        ImageEngine imageEngine;
        LocalMedia item = getItem(i2);
        if (item != null) {
            viewHolder.viewBorder.setVisibility(item.isChecked() ? 0 : 8);
            if (this.config != null && (imageEngine = PictureSelectionConfig.imageEngine) != null) {
                imageEngine.loadImage(viewHolder.itemView.getContext(), item.getPath(), viewHolder.ivImage);
            }
            viewHolder.ivPlay.setVisibility(PictureMimeType.isHasVideo(item.getMimeType()) ? 0 : 8);
            viewHolder.itemView.setOnClickListener(new View.OnClickListener() { // from class: b.t.a.a.h0.i
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    PictureWeChatPreviewGalleryAdapter.this.m4540a(viewHolder, i2, view);
                }
            });
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    @NonNull
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup viewGroup, int i2) {
        return new ViewHolder(LayoutInflater.from(viewGroup.getContext()).inflate(C3979R.layout.picture_wechat_preview_gallery, viewGroup, false));
    }
}
