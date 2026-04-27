package im.uwrkaxlmjj.ui.components;

import android.content.Context;
import android.graphics.drawable.Drawable;
import android.util.SparseArray;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MediaDataController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.ContentPreviewViewer;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.cells.EmptyCell;
import im.uwrkaxlmjj.ui.cells.StickerEmojiCell;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.ScrollSlidingTabStrip;
import java.util.ArrayList;
import java.util.HashMap;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class StickerMasksView extends FrameLayout implements NotificationCenter.NotificationCenterDelegate {
    private int currentAccount;
    private int currentType;
    private int lastNotifyWidth;
    private Listener listener;
    private ArrayList<TLRPC.Document>[] recentStickers;
    private int recentTabBum;
    private ScrollSlidingTabStrip scrollSlidingTabStrip;
    private ArrayList<TLRPC.TL_messages_stickerSet>[] stickerSets;
    private TextView stickersEmptyView;
    private StickersGridAdapter stickersGridAdapter;
    private RecyclerListView stickersGridView;
    private GridLayoutManager stickersLayoutManager;
    private RecyclerListView.OnItemClickListener stickersOnItemClickListener;
    private int stickersTabOffset;

    public interface Listener {
        void onStickerSelected(Object obj, TLRPC.Document document);

        void onTypeChanged();
    }

    public StickerMasksView(Context context) {
        super(context);
        this.currentAccount = UserConfig.selectedAccount;
        this.stickerSets = new ArrayList[]{new ArrayList<>(), new ArrayList<>()};
        this.recentStickers = new ArrayList[]{new ArrayList<>(), new ArrayList<>()};
        this.currentType = 1;
        this.recentTabBum = -2;
        setBackgroundColor(-14540254);
        setClickable(true);
        MediaDataController.getInstance(this.currentAccount).checkStickers(0);
        MediaDataController.getInstance(this.currentAccount).checkStickers(1);
        RecyclerListView recyclerListView = new RecyclerListView(context) { // from class: im.uwrkaxlmjj.ui.components.StickerMasksView.1
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup
            public boolean onInterceptTouchEvent(MotionEvent event) {
                boolean result = ContentPreviewViewer.getInstance().onInterceptTouchEvent(event, StickerMasksView.this.stickersGridView, StickerMasksView.this.getMeasuredHeight(), null);
                return super.onInterceptTouchEvent(event) || result;
            }
        };
        this.stickersGridView = recyclerListView;
        GridLayoutManager gridLayoutManager = new GridLayoutManager(context, 5);
        this.stickersLayoutManager = gridLayoutManager;
        recyclerListView.setLayoutManager(gridLayoutManager);
        this.stickersLayoutManager.setSpanSizeLookup(new GridLayoutManager.SpanSizeLookup() { // from class: im.uwrkaxlmjj.ui.components.StickerMasksView.2
            @Override // androidx.recyclerview.widget.GridLayoutManager.SpanSizeLookup
            public int getSpanSize(int position) {
                if (position != StickerMasksView.this.stickersGridAdapter.totalItems) {
                    return 1;
                }
                return StickerMasksView.this.stickersGridAdapter.stickersPerRow;
            }
        });
        this.stickersGridView.setPadding(0, AndroidUtilities.dp(4.0f), 0, 0);
        this.stickersGridView.setClipToPadding(false);
        RecyclerListView recyclerListView2 = this.stickersGridView;
        StickersGridAdapter stickersGridAdapter = new StickersGridAdapter(context);
        this.stickersGridAdapter = stickersGridAdapter;
        recyclerListView2.setAdapter(stickersGridAdapter);
        this.stickersGridView.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$StickerMasksView$MdO5_lKLHmlzqddTTG1ljbz_vbg
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view, MotionEvent motionEvent) {
                return this.f$0.lambda$new$0$StickerMasksView(view, motionEvent);
            }
        });
        RecyclerListView.OnItemClickListener onItemClickListener = new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$StickerMasksView$bryD8sc_FeFoNSxf7cSckGQNMgI
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$new$1$StickerMasksView(view, i);
            }
        };
        this.stickersOnItemClickListener = onItemClickListener;
        this.stickersGridView.setOnItemClickListener(onItemClickListener);
        this.stickersGridView.setGlowColor(-657673);
        addView(this.stickersGridView, LayoutHelper.createFrame(-1.0f, -1.0f, 51, 0.0f, 48.0f, 0.0f, 0.0f));
        TextView textView = new TextView(context);
        this.stickersEmptyView = textView;
        textView.setTextSize(1, 18.0f);
        this.stickersEmptyView.setTextColor(-7829368);
        addView(this.stickersEmptyView, LayoutHelper.createFrame(-2.0f, -2.0f, 17, 0.0f, 48.0f, 0.0f, 0.0f));
        this.stickersGridView.setEmptyView(this.stickersEmptyView);
        ScrollSlidingTabStrip scrollSlidingTabStrip = new ScrollSlidingTabStrip(context);
        this.scrollSlidingTabStrip = scrollSlidingTabStrip;
        scrollSlidingTabStrip.setBackgroundColor(-16777216);
        this.scrollSlidingTabStrip.setUnderlineHeight(AndroidUtilities.dp(1.0f));
        this.scrollSlidingTabStrip.setIndicatorColor(-10305560);
        this.scrollSlidingTabStrip.setUnderlineColor(-15066598);
        this.scrollSlidingTabStrip.setIndicatorHeight(AndroidUtilities.dp(1.0f) + 1);
        addView(this.scrollSlidingTabStrip, LayoutHelper.createFrame(-1, 48, 51));
        updateStickerTabs();
        this.scrollSlidingTabStrip.setDelegate(new ScrollSlidingTabStrip.ScrollSlidingTabStripDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$StickerMasksView$QHkqGM3qKazrzxt1eoBp6P23Zzk
            @Override // im.uwrkaxlmjj.ui.components.ScrollSlidingTabStrip.ScrollSlidingTabStripDelegate
            public final void onPageSelected(int i) {
                this.f$0.lambda$new$2$StickerMasksView(i);
            }
        });
        this.stickersGridView.setOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.components.StickerMasksView.3
            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
                StickerMasksView.this.checkScroll();
            }
        });
    }

    public /* synthetic */ boolean lambda$new$0$StickerMasksView(View v, MotionEvent event) {
        return ContentPreviewViewer.getInstance().onTouch(event, this.stickersGridView, getMeasuredHeight(), this.stickersOnItemClickListener, null);
    }

    public /* synthetic */ void lambda$new$1$StickerMasksView(View view, int position) {
        if (!(view instanceof StickerEmojiCell)) {
            return;
        }
        ContentPreviewViewer.getInstance().reset();
        StickerEmojiCell cell = (StickerEmojiCell) view;
        if (cell.isDisabled()) {
            return;
        }
        TLRPC.Document document = cell.getSticker();
        Object parent = cell.getParentObject();
        this.listener.onStickerSelected(parent, document);
        MediaDataController.getInstance(this.currentAccount).addRecentSticker(1, parent, document, (int) (System.currentTimeMillis() / 1000), false);
        MessagesController.getInstance(this.currentAccount).saveRecentSticker(parent, document, true);
    }

    public /* synthetic */ void lambda$new$2$StickerMasksView(int page) {
        if (page != 0) {
            if (page == this.recentTabBum + 1) {
                this.stickersLayoutManager.scrollToPositionWithOffset(0, 0);
                return;
            }
            int index = (page - 1) - this.stickersTabOffset;
            if (index >= this.stickerSets[this.currentType].size()) {
                index = this.stickerSets[this.currentType].size() - 1;
            }
            this.stickersLayoutManager.scrollToPositionWithOffset(this.stickersGridAdapter.getPositionForPack(this.stickerSets[this.currentType].get(index)), 0);
            checkScroll();
            return;
        }
        if (this.currentType == 0) {
            this.currentType = 1;
        } else {
            this.currentType = 0;
        }
        Listener listener = this.listener;
        if (listener != null) {
            listener.onTypeChanged();
        }
        this.recentStickers[this.currentType] = MediaDataController.getInstance(this.currentAccount).getRecentStickers(this.currentType);
        this.stickersLayoutManager.scrollToPositionWithOffset(0, 0);
        updateStickerTabs();
        reloadStickersAdapter();
        checkDocuments();
        checkPanels();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void checkScroll() {
        int firstVisibleItem = this.stickersLayoutManager.findFirstVisibleItemPosition();
        if (firstVisibleItem == -1) {
            return;
        }
        checkStickersScroll(firstVisibleItem);
    }

    private void checkStickersScroll(int firstVisibleItem) {
        if (this.stickersGridView == null) {
            return;
        }
        ScrollSlidingTabStrip scrollSlidingTabStrip = this.scrollSlidingTabStrip;
        int tabForPosition = this.stickersGridAdapter.getTabForPosition(firstVisibleItem) + 1;
        int i = this.recentTabBum;
        if (i <= 0) {
            i = this.stickersTabOffset;
        }
        scrollSlidingTabStrip.onPageScrolled(tabForPosition, i + 1);
    }

    public int getCurrentType() {
        return this.currentType;
    }

    private void updateStickerTabs() {
        ScrollSlidingTabStrip scrollSlidingTabStrip = this.scrollSlidingTabStrip;
        if (scrollSlidingTabStrip == null) {
            return;
        }
        this.recentTabBum = -2;
        this.stickersTabOffset = 0;
        int lastPosition = scrollSlidingTabStrip.getCurrentPosition();
        this.scrollSlidingTabStrip.removeTabs();
        if (this.currentType == 0) {
            Drawable drawable = getContext().getResources().getDrawable(R.drawable.ic_masks_msk1);
            Theme.setDrawableColorByKey(drawable, Theme.key_chat_emojiPanelIcon);
            this.scrollSlidingTabStrip.addIconTab(drawable);
            this.stickersEmptyView.setText(LocaleController.getString("NoStickers", R.string.NoStickers));
        } else {
            Drawable drawable2 = getContext().getResources().getDrawable(R.drawable.ic_masks_sticker1);
            Theme.setDrawableColorByKey(drawable2, Theme.key_chat_emojiPanelIcon);
            this.scrollSlidingTabStrip.addIconTab(drawable2);
            this.stickersEmptyView.setText(LocaleController.getString("NoMasks", R.string.NoMasks));
        }
        if (!this.recentStickers[this.currentType].isEmpty()) {
            int i = this.stickersTabOffset;
            this.recentTabBum = i;
            this.stickersTabOffset = i + 1;
            this.scrollSlidingTabStrip.addIconTab(Theme.createEmojiIconSelectorDrawable(getContext(), R.drawable.ic_masks_recent1, Theme.getColor(Theme.key_chat_emojiPanelMasksIcon), Theme.getColor(Theme.key_chat_emojiPanelMasksIconSelected)));
        }
        this.stickerSets[this.currentType].clear();
        ArrayList<TLRPC.TL_messages_stickerSet> packs = MediaDataController.getInstance(this.currentAccount).getStickerSets(this.currentType);
        for (int a = 0; a < packs.size(); a++) {
            TLRPC.TL_messages_stickerSet pack = packs.get(a);
            if (!pack.set.archived && pack.documents != null && !pack.documents.isEmpty()) {
                this.stickerSets[this.currentType].add(pack);
            }
        }
        for (int a2 = 0; a2 < this.stickerSets[this.currentType].size(); a2++) {
            TLRPC.TL_messages_stickerSet set = this.stickerSets[this.currentType].get(a2);
            TLRPC.Document document = set.documents.get(0);
            this.scrollSlidingTabStrip.addStickerTab(document, document, set);
        }
        this.scrollSlidingTabStrip.updateTabStyles();
        if (lastPosition != 0) {
            this.scrollSlidingTabStrip.onPageScrolled(lastPosition, lastPosition);
        }
        checkPanels();
    }

    private void checkPanels() {
        int position;
        if (this.scrollSlidingTabStrip != null && (position = this.stickersLayoutManager.findFirstVisibleItemPosition()) != -1) {
            ScrollSlidingTabStrip scrollSlidingTabStrip = this.scrollSlidingTabStrip;
            int tabForPosition = this.stickersGridAdapter.getTabForPosition(position) + 1;
            int i = this.recentTabBum;
            if (i <= 0) {
                i = this.stickersTabOffset;
            }
            scrollSlidingTabStrip.onPageScrolled(tabForPosition, i + 1);
        }
    }

    public void addRecentSticker(TLRPC.Document document) {
        if (document == null) {
            return;
        }
        MediaDataController.getInstance(this.currentAccount).addRecentSticker(this.currentType, null, document, (int) (System.currentTimeMillis() / 1000), false);
        boolean wasEmpty = this.recentStickers[this.currentType].isEmpty();
        this.recentStickers[this.currentType] = MediaDataController.getInstance(this.currentAccount).getRecentStickers(this.currentType);
        StickersGridAdapter stickersGridAdapter = this.stickersGridAdapter;
        if (stickersGridAdapter != null) {
            stickersGridAdapter.notifyDataSetChanged();
        }
        if (wasEmpty) {
            updateStickerTabs();
        }
    }

    @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
    protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
        if (this.lastNotifyWidth != right - left) {
            this.lastNotifyWidth = right - left;
            reloadStickersAdapter();
        }
        super.onLayout(changed, left, top, right, bottom);
    }

    private void reloadStickersAdapter() {
        StickersGridAdapter stickersGridAdapter = this.stickersGridAdapter;
        if (stickersGridAdapter != null) {
            stickersGridAdapter.notifyDataSetChanged();
        }
        if (ContentPreviewViewer.getInstance().isVisible()) {
            ContentPreviewViewer.getInstance().close();
        }
        ContentPreviewViewer.getInstance().reset();
    }

    public void setListener(Listener value) {
        this.listener = value;
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.stickersDidLoad);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.recentImagesDidLoad);
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$StickerMasksView$D392nYWDo7T8f2VyVxWs0YPGiNg
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$onAttachedToWindow$3$StickerMasksView();
            }
        });
    }

    public /* synthetic */ void lambda$onAttachedToWindow$3$StickerMasksView() {
        updateStickerTabs();
        reloadStickersAdapter();
    }

    @Override // android.view.View
    public void setVisibility(int visibility) {
        super.setVisibility(visibility);
        if (visibility != 8) {
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.stickersDidLoad);
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.recentDocumentsDidLoad);
            updateStickerTabs();
            reloadStickersAdapter();
            checkDocuments();
            MediaDataController.getInstance(this.currentAccount).loadRecents(0, false, true, false);
            MediaDataController.getInstance(this.currentAccount).loadRecents(1, false, true, false);
            MediaDataController.getInstance(this.currentAccount).loadRecents(2, false, true, false);
        }
    }

    public void onDestroy() {
        if (this.stickersGridAdapter != null) {
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.stickersDidLoad);
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.recentDocumentsDidLoad);
        }
    }

    private void checkDocuments() {
        int previousCount = this.recentStickers[this.currentType].size();
        this.recentStickers[this.currentType] = MediaDataController.getInstance(this.currentAccount).getRecentStickers(this.currentType);
        StickersGridAdapter stickersGridAdapter = this.stickersGridAdapter;
        if (stickersGridAdapter != null) {
            stickersGridAdapter.notifyDataSetChanged();
        }
        if (previousCount != this.recentStickers[this.currentType].size()) {
            updateStickerTabs();
        }
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.stickersDidLoad) {
            if (((Integer) args[0]).intValue() == this.currentType) {
                updateStickerTabs();
                reloadStickersAdapter();
                checkPanels();
                return;
            }
            return;
        }
        if (id == NotificationCenter.recentDocumentsDidLoad) {
            boolean isGif = ((Boolean) args[0]).booleanValue();
            if (!isGif && ((Integer) args[1]).intValue() == this.currentType) {
                checkDocuments();
            }
        }
    }

    private class StickersGridAdapter extends RecyclerListView.SelectionAdapter {
        private Context context;
        private int stickersPerRow;
        private int totalItems;
        private SparseArray<TLRPC.TL_messages_stickerSet> rowStartPack = new SparseArray<>();
        private HashMap<TLRPC.TL_messages_stickerSet, Integer> packStartRow = new HashMap<>();
        private SparseArray<TLRPC.Document> cache = new SparseArray<>();
        private SparseArray<TLRPC.TL_messages_stickerSet> positionsToSets = new SparseArray<>();

        public StickersGridAdapter(Context context) {
            this.context = context;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            int i = this.totalItems;
            if (i != 0) {
                return i + 1;
            }
            return 0;
        }

        public Object getItem(int i) {
            return this.cache.get(i);
        }

        public int getPositionForPack(TLRPC.TL_messages_stickerSet stickerSet) {
            return this.packStartRow.get(stickerSet).intValue() * this.stickersPerRow;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (this.cache.get(position) != null) {
                return 0;
            }
            return 1;
        }

        public int getTabForPosition(int position) {
            if (this.stickersPerRow == 0) {
                int width = StickerMasksView.this.getMeasuredWidth();
                if (width == 0) {
                    width = AndroidUtilities.displaySize.x;
                }
                this.stickersPerRow = width / AndroidUtilities.dp(72.0f);
            }
            int row = position / this.stickersPerRow;
            TLRPC.TL_messages_stickerSet pack = this.rowStartPack.get(row);
            return pack == null ? StickerMasksView.this.recentTabBum : StickerMasksView.this.stickerSets[StickerMasksView.this.currentType].indexOf(pack) + StickerMasksView.this.stickersTabOffset;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return false;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view = null;
            if (viewType == 0) {
                view = new StickerEmojiCell(this.context) { // from class: im.uwrkaxlmjj.ui.components.StickerMasksView.StickersGridAdapter.1
                    @Override // android.widget.FrameLayout, android.view.View
                    public void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                        super.onMeasure(widthMeasureSpec, View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(82.0f), 1073741824));
                    }
                };
            } else if (viewType == 1) {
                view = new EmptyCell(this.context);
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            int itemViewType = holder.getItemViewType();
            if (itemViewType == 0) {
                TLRPC.Document sticker = this.cache.get(position);
                ((StickerEmojiCell) holder.itemView).setSticker(sticker, this.positionsToSets.get(position), false);
                return;
            }
            if (itemViewType == 1) {
                if (position == this.totalItems) {
                    int row = (position - 1) / this.stickersPerRow;
                    TLRPC.TL_messages_stickerSet pack = this.rowStartPack.get(row);
                    if (pack != null) {
                        int height = StickerMasksView.this.stickersGridView.getMeasuredHeight() - (((int) Math.ceil(pack.documents.size() / this.stickersPerRow)) * AndroidUtilities.dp(82.0f));
                        ((EmptyCell) holder.itemView).setHeight(height > 0 ? height : 1);
                        return;
                    } else {
                        ((EmptyCell) holder.itemView).setHeight(1);
                        return;
                    }
                }
                ((EmptyCell) holder.itemView).setHeight(AndroidUtilities.dp(82.0f));
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void notifyDataSetChanged() {
            ArrayList<TLRPC.Document> documents;
            int width = StickerMasksView.this.getMeasuredWidth();
            if (width == 0) {
                width = AndroidUtilities.displaySize.x;
            }
            this.stickersPerRow = width / AndroidUtilities.dp(72.0f);
            StickerMasksView.this.stickersLayoutManager.setSpanCount(this.stickersPerRow);
            this.rowStartPack.clear();
            this.packStartRow.clear();
            this.cache.clear();
            this.positionsToSets.clear();
            this.totalItems = 0;
            ArrayList<TLRPC.TL_messages_stickerSet> packs = StickerMasksView.this.stickerSets[StickerMasksView.this.currentType];
            for (int a = -1; a < packs.size(); a++) {
                TLRPC.TL_messages_stickerSet pack = null;
                int startRow = this.totalItems / this.stickersPerRow;
                if (a == -1) {
                    documents = StickerMasksView.this.recentStickers[StickerMasksView.this.currentType];
                } else {
                    TLRPC.TL_messages_stickerSet pack2 = packs.get(a);
                    pack = pack2;
                    documents = pack.documents;
                    this.packStartRow.put(pack, Integer.valueOf(startRow));
                }
                if (!documents.isEmpty()) {
                    int count = (int) Math.ceil(documents.size() / this.stickersPerRow);
                    for (int b = 0; b < documents.size(); b++) {
                        this.cache.put(this.totalItems + b, documents.get(b));
                        this.positionsToSets.put(this.totalItems + b, pack);
                    }
                    int b2 = this.totalItems;
                    this.totalItems = b2 + (this.stickersPerRow * count);
                    for (int b3 = 0; b3 < count; b3++) {
                        this.rowStartPack.put(startRow + b3, pack);
                    }
                }
            }
            super.notifyDataSetChanged();
        }
    }
}
