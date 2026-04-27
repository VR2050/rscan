package im.uwrkaxlmjj.ui.hui.adapter.pageAdapter;

import android.content.Context;
import android.view.View;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.decoration.StickyXDecoration;
import im.uwrkaxlmjj.ui.decoration.cache.CacheUtil;
import im.uwrkaxlmjj.ui.decoration.listener.GroupXListener;
import im.uwrkaxlmjj.ui.decoration.listener.OnGroupClickListener;
import im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageHolder;

/* JADX INFO: loaded from: classes5.dex */
public abstract class PageStickerAdapter<T, VH extends PageHolder> extends PageSelectionAdapter<T, VH> implements GroupXListener, OnGroupClickListener {
    private boolean mAutoAddSticker;
    private boolean mHasAddStickerDeration;
    private RecyclerView mRv;
    private CacheUtil<String> mStickerCache;
    private CacheUtil<PageHolder> mStickerHeaderCache;
    private int mStickerHeight;

    protected abstract View getStickerHeader(int i, T t);

    protected abstract String getStickerName(int i, T t);

    protected abstract void onBindStickerHeaderHolder(PageHolder pageHolder, int i, T t);

    public PageStickerAdapter(Context context) {
        super(context);
        this.mAutoAddSticker = true;
        this.mStickerCache = new CacheUtil<>();
        this.mStickerHeaderCache = new CacheUtil<>();
    }

    private void cleanCache() {
        CacheUtil<String> cacheUtil = this.mStickerCache;
        if (cacheUtil == null) {
            this.mStickerCache = new CacheUtil<>();
        } else {
            cacheUtil.clean();
        }
        CacheUtil<PageHolder> cacheUtil2 = this.mStickerHeaderCache;
        if (cacheUtil2 == null) {
            this.mStickerHeaderCache = new CacheUtil<>();
        } else {
            cacheUtil2.clean();
        }
    }

    private void setStickerDeration() {
        RecyclerView recyclerView;
        if (this.mAutoAddSticker && (recyclerView = this.mRv) != null && !this.mHasAddStickerDeration) {
            this.mHasAddStickerDeration = true;
            recyclerView.addItemDecoration(getDefaultStickerDecoration(this.mStickerHeight));
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public void notifyDataSetChanged() {
        super.notifyDataSetChanged();
        cleanCache();
    }

    @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter, androidx.recyclerview.widget.RecyclerView.Adapter
    public void onAttachedToRecyclerView(RecyclerView recyclerView) {
        super.onAttachedToRecyclerView(recyclerView);
        this.mRv = recyclerView;
        setStickerDeration();
    }

    @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter
    public void reLoadData() {
        super.reLoadData();
        cleanCache();
    }

    @Override // im.uwrkaxlmjj.ui.decoration.listener.GroupXListener
    public final View getGroupView(int position) {
        PageHolder holder;
        View view = null;
        if (position >= 0 && position < getData().size()) {
            T item = getData().get(position);
            if (this.mStickerHeaderCache.get(position) == null) {
                view = getStickerHeader(position, item);
                holder = new PageHolder(view);
                this.mStickerHeaderCache.put(position, holder);
            } else {
                holder = this.mStickerHeaderCache.get(position);
                view = holder.itemView;
            }
            onBindStickerHeaderHolder(holder, position, item);
        }
        return view;
    }

    @Override // im.uwrkaxlmjj.ui.decoration.listener.GroupListener
    public final String getGroupName(int position) {
        String name = null;
        int count = getItemCount();
        if (position >= 0 && position < count && (name = this.mStickerCache.get(position)) == null) {
            if (position < getData().size()) {
                name = getStickerName(position, getItem(position));
            }
            if (name == null) {
                name = getGroupName(position - 1);
            }
            try {
                this.mStickerCache.put(position, name == null ? "" : name);
            } catch (Exception e) {
                FileLog.e("PageSelectionAdapter =====> " + e.getMessage());
            }
        }
        return name;
    }

    @Override // im.uwrkaxlmjj.ui.decoration.listener.OnGroupClickListener
    public void onClick(int position, int viewId) {
    }

    public int getStickerHeight() {
        return this.mStickerHeight;
    }

    public PageStickerAdapter<T, VH> setStickerHeight(int stickerHeight) {
        this.mStickerHeight = stickerHeight;
        return this;
    }

    public PageStickerAdapter<T, VH> setAutoAddSticker(boolean autoAddSticker) {
        this.mAutoAddSticker = autoAddSticker;
        return this;
    }

    public StickyXDecoration getDefaultStickerDecoration(int stickerHeight) {
        return getDefaultStickerDecoration(stickerHeight, true);
    }

    public StickyXDecoration getDefaultStickerDecoration(int stickerHeight, boolean isDpValue) {
        this.mStickerHeight = stickerHeight;
        StickyXDecoration.Builder decorationBuilder = StickyXDecoration.Builder.init(this).setOnClickListener(this).setGroupBackground(Theme.getColor(Theme.key_list_decorationBackground));
        if (stickerHeight > 0) {
            decorationBuilder.setGroupHeight(isDpValue ? AndroidUtilities.dp(stickerHeight) : stickerHeight);
        }
        return decorationBuilder.build();
    }

    @Override // im.uwrkaxlmjj.ui.hui.adapter.pageAdapter.PageSelectionAdapter
    public void destroy() {
        super.destroy();
        cleanCache();
        this.mRv = null;
    }
}
