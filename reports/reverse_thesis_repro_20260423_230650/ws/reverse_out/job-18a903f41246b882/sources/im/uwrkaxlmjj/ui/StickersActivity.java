package im.uwrkaxlmjj.ui;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.drawable.Drawable;
import android.text.SpannableStringBuilder;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.recyclerview.widget.ItemTouchHelper;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.just.agentweb.DefaultWebClient;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MediaDataController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.SharedConfig;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.cells.ShadowSectionCell;
import im.uwrkaxlmjj.ui.cells.StickerSetCell;
import im.uwrkaxlmjj.ui.cells.TextCheckCell;
import im.uwrkaxlmjj.ui.cells.TextInfoPrivacyCell;
import im.uwrkaxlmjj.ui.cells.TextSettingsCell;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.StickersAlert;
import im.uwrkaxlmjj.ui.components.URLSpanNoUnderline;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.dialogs.DialogCommonList;
import im.uwrkaxlmjj.ui.hcells.MryTextCheckCell;
import im.uwrkaxlmjj.ui.hcells.TextSettingCell;
import im.uwrkaxlmjj.ui.hui.decoration.TopBottomDecoration;
import im.uwrkaxlmjj.ui.hviews.slidemenu.SwipeLayout;
import im.uwrkaxlmjj.ui.hviews.swipelist.SlidingItemMenuRecyclerView;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class StickersActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate {
    private int archivedInfoRow;
    private int archivedRow;
    private int currentType;
    private int featuredInfoRow;
    private int featuredRow;
    private LinearLayoutManager layoutManager;
    private ListAdapter listAdapter;
    private RecyclerListView listView;
    private int loopInfoRow;
    private int loopRow;
    private int masksInfoRow = -1;
    private int masksRow;
    private boolean needReorder;
    private int rowCount;
    private int stickersEndRow;
    private int stickersStartRow;
    private int suggestInfoRow;
    private int suggestRow;
    private int yourStickerBagInfoRow;

    public class TouchHelperCallback extends ItemTouchHelper.Callback {
        public TouchHelperCallback() {
        }

        @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
        public boolean isLongPressDragEnabled() {
            return true;
        }

        @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
        public int getMovementFlags(RecyclerView recyclerView, RecyclerView.ViewHolder viewHolder) {
            if (viewHolder.getItemViewType() != 0) {
                return makeMovementFlags(0, 0);
            }
            return makeMovementFlags(3, 0);
        }

        @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
        public boolean onMove(RecyclerView recyclerView, RecyclerView.ViewHolder source, RecyclerView.ViewHolder target) {
            if (source.getItemViewType() == target.getItemViewType()) {
                StickersActivity.this.listAdapter.swapElements(source.getAdapterPosition(), target.getAdapterPosition());
                return true;
            }
            return false;
        }

        @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
        public void onChildDraw(Canvas c, RecyclerView recyclerView, RecyclerView.ViewHolder viewHolder, float dX, float dY, int actionState, boolean isCurrentlyActive) {
            super.onChildDraw(c, recyclerView, viewHolder, dX, dY, actionState, isCurrentlyActive);
        }

        @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
        public void onSelectedChanged(RecyclerView.ViewHolder viewHolder, int actionState) {
            if (actionState != 0) {
                StickersActivity.this.listView.cancelClickRunnables(false);
                viewHolder.itemView.setPressed(true);
            }
            super.onSelectedChanged(viewHolder, actionState);
        }

        @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
        public void onSwiped(RecyclerView.ViewHolder viewHolder, int direction) {
        }

        @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
        public void clearView(RecyclerView recyclerView, RecyclerView.ViewHolder viewHolder) {
            super.clearView(recyclerView, viewHolder);
            viewHolder.itemView.setPressed(false);
        }
    }

    public StickersActivity(int type) {
        this.currentType = type;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        MediaDataController.getInstance(this.currentAccount).checkStickers(this.currentType);
        if (this.currentType == 0) {
            MediaDataController.getInstance(this.currentAccount).checkFeaturedStickers();
        }
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.stickersDidLoad);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.archivedStickersCountDidLoad);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.featuredStickersDidLoad);
        updateRows();
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.stickersDidLoad);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.archivedStickersCountDidLoad);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.featuredStickersDidLoad);
        sendReorder();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setAllowOverlayTitle(true);
        if (this.currentType == 0) {
            this.actionBar.setTitle(LocaleController.getString("StickersSetting", R.string.StickersSetting));
        } else {
            this.actionBar.setTitle(LocaleController.getString("Masks", R.string.Masks));
        }
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.StickersActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    StickersActivity.this.finishFragment();
                }
            }
        });
        this.listAdapter = new ListAdapter(context);
        this.fragmentView = new FrameLayout(context);
        FrameLayout frameLayout = (FrameLayout) this.fragmentView;
        frameLayout.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        RecyclerListView recyclerListView = new RecyclerListView(context);
        this.listView = recyclerListView;
        recyclerListView.addItemDecoration(new TopBottomDecoration(10, 0));
        this.listView.setFocusable(true);
        this.listView.setTag(7);
        this.listView.setOverScrollMode(2);
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(context);
        this.layoutManager = linearLayoutManager;
        linearLayoutManager.setOrientation(1);
        this.listView.setLayoutManager(this.layoutManager);
        ItemTouchHelper itemTouchHelper = new ItemTouchHelper(new TouchHelperCallback());
        itemTouchHelper.attachToRecyclerView(this.listView);
        frameLayout.addView(this.listView, LayoutHelper.createFrame(-1, -1, AndroidUtilities.dp(10.0f), 0, AndroidUtilities.dp(10.0f), 0));
        this.listView.setAdapter(this.listAdapter);
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$StickersActivity$SxH0MVD1IBPi_Sa2yn-CkS7EIjI
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$createView$0$StickersActivity(view, i);
            }
        });
        return this.fragmentView;
    }

    public /* synthetic */ void lambda$createView$0$StickersActivity(View view, int position) {
        if (position >= this.stickersStartRow && position < this.stickersEndRow && getParentActivity() != null) {
            sendReorder();
            TLRPC.TL_messages_stickerSet stickerSet = MediaDataController.getInstance(this.currentAccount).getStickerSets(this.currentType).get(position - this.stickersStartRow);
            ArrayList<TLRPC.Document> stickers = stickerSet.documents;
            if (stickers == null || stickers.isEmpty()) {
                return;
            }
            showDialog(new StickersAlert(getParentActivity(), this, null, stickerSet, null));
            return;
        }
        if (position == this.featuredRow) {
            sendReorder();
            presentFragment(new FeaturedStickersActivity());
            return;
        }
        if (position == this.archivedRow) {
            sendReorder();
            presentFragment(new ArchivedStickersActivity(this.currentType));
            return;
        }
        if (position == this.masksRow) {
            presentFragment(new StickersActivity(1));
            return;
        }
        if (position == this.suggestRow) {
            showAlert();
        } else if (position == this.loopRow) {
            SharedConfig.toggleLoopStickers();
            if (view instanceof MryTextCheckCell) {
                ((MryTextCheckCell) view).setChecked(SharedConfig.loopStickers);
            }
        }
    }

    private void showAlert() {
        List<String> list = new ArrayList<>();
        list.add(LocaleController.getString("SuggestStickersAll", R.string.SuggestStickersAll));
        list.add(LocaleController.getString("SuggestStickersInstalled", R.string.SuggestStickersInstalled));
        list.add(LocaleController.getString("SuggestStickersNone", R.string.SuggestStickersNone));
        DialogCommonList dialogCommonList = new DialogCommonList(getParentActivity(), list, (List<Integer>) null, Color.parseColor("#3BBCFF"), new DialogCommonList.RecyclerviewItemClickCallBack() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$StickersActivity$1Mx5O8cpC_Vn9pTB65P64yoaTlU
            @Override // im.uwrkaxlmjj.ui.dialogs.DialogCommonList.RecyclerviewItemClickCallBack
            public final void onRecyclerviewItemClick(int i) {
                this.f$0.lambda$showAlert$1$StickersActivity(i);
            }
        }, 1);
        dialogCommonList.setTitle(LocaleController.getString("SuggestStickers", R.string.SuggestStickers), -7631463, 15);
        dialogCommonList.show();
    }

    public /* synthetic */ void lambda$showAlert$1$StickersActivity(int position) {
        SharedConfig.setSuggestStickers(position);
        this.listAdapter.notifyItemChanged(this.suggestRow);
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.stickersDidLoad) {
            if (((Integer) args[0]).intValue() == this.currentType) {
                updateRows();
            }
        } else {
            if (id == NotificationCenter.featuredStickersDidLoad) {
                ListAdapter listAdapter = this.listAdapter;
                if (listAdapter != null) {
                    listAdapter.notifyItemChanged(0);
                    return;
                }
                return;
            }
            if (id == NotificationCenter.archivedStickersCountDidLoad && ((Integer) args[0]).intValue() == this.currentType) {
                updateRows();
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void sendReorder() {
        if (!this.needReorder) {
            return;
        }
        MediaDataController.getInstance(this.currentAccount).calcNewHash(this.currentType);
        this.needReorder = false;
        TLRPC.TL_messages_reorderStickerSets req = new TLRPC.TL_messages_reorderStickerSets();
        req.masks = this.currentType == 1;
        ArrayList<TLRPC.TL_messages_stickerSet> arrayList = MediaDataController.getInstance(this.currentAccount).getStickerSets(this.currentType);
        for (int a = 0; a < arrayList.size(); a++) {
            req.order.add(Long.valueOf(arrayList.get(a).set.id));
        }
        int a2 = this.currentAccount;
        ConnectionsManager.getInstance(a2).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$StickersActivity$z9yEOYaQdbeftJkAiRWtpELTW_Q
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                StickersActivity.lambda$sendReorder$2(tLObject, tL_error);
            }
        });
        NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.stickersDidLoad, Integer.valueOf(this.currentType));
    }

    static /* synthetic */ void lambda$sendReorder$2(TLObject response, TLRPC.TL_error error) {
    }

    private void updateRows() {
        this.rowCount = 0;
        this.suggestInfoRow = -1;
        this.masksInfoRow = -1;
        this.yourStickerBagInfoRow = -1;
        if (this.currentType == 0) {
            int i = 0 + 1;
            this.rowCount = i;
            this.suggestRow = 0;
            int i2 = i + 1;
            this.rowCount = i2;
            this.featuredRow = i;
            int i3 = i2 + 1;
            this.rowCount = i3;
            this.masksRow = i2;
            int i4 = i3 + 1;
            this.rowCount = i4;
            this.loopRow = i3;
            this.rowCount = i4 + 1;
            this.loopInfoRow = i4;
        } else {
            this.featuredRow = -1;
            this.featuredInfoRow = -1;
            this.masksRow = -1;
            this.loopRow = -1;
        }
        if (MediaDataController.getInstance(this.currentAccount).getArchivedStickersCount(this.currentType) != 0) {
            int i5 = this.rowCount;
            int i6 = i5 + 1;
            this.rowCount = i6;
            this.archivedRow = i5;
            this.rowCount = i6 + 1;
            this.archivedInfoRow = i6;
        } else {
            this.archivedRow = -1;
            this.archivedInfoRow = -1;
        }
        ArrayList<TLRPC.TL_messages_stickerSet> stickerSets = MediaDataController.getInstance(this.currentAccount).getStickerSets(this.currentType);
        if (!stickerSets.isEmpty()) {
            if (this.currentType == 0) {
                int i7 = this.rowCount;
                this.rowCount = i7 + 1;
                this.yourStickerBagInfoRow = i7;
            }
            int i8 = this.rowCount;
            this.stickersStartRow = i8;
            this.stickersEndRow = i8 + stickerSets.size();
            int size = this.rowCount + stickerSets.size();
            this.rowCount = size;
            if (this.currentType == 0) {
                this.rowCount = size + 1;
                this.featuredInfoRow = size;
            }
        } else {
            this.stickersStartRow = -1;
            this.stickersEndRow = -1;
            this.featuredInfoRow = -1;
        }
        if (this.currentType == 1) {
            int i9 = this.rowCount;
            this.rowCount = i9 + 1;
            this.masksInfoRow = i9;
        }
        ListAdapter listAdapter = this.listAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        ListAdapter listAdapter = this.listAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        public ListAdapter(Context context) {
            this.mContext = context;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return StickersActivity.this.rowCount;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public long getItemId(int i) {
            if (i < StickersActivity.this.stickersStartRow || i >= StickersActivity.this.stickersEndRow) {
                if (i == StickersActivity.this.suggestRow || i == StickersActivity.this.suggestInfoRow || i == StickersActivity.this.archivedRow || i == StickersActivity.this.archivedInfoRow || i == StickersActivity.this.featuredRow || i == StickersActivity.this.featuredInfoRow || i == StickersActivity.this.masksRow || i == StickersActivity.this.masksInfoRow) {
                    return -2147483648L;
                }
                return i;
            }
            ArrayList<TLRPC.TL_messages_stickerSet> arrayList = MediaDataController.getInstance(StickersActivity.this.currentAccount).getStickerSets(StickersActivity.this.currentType);
            return arrayList.get(i - StickersActivity.this.stickersStartRow).set.id;
        }

        private void processSelectionOption(int which, TLRPC.TL_messages_stickerSet stickerSet) {
            if (which == 0) {
                MediaDataController.getInstance(StickersActivity.this.currentAccount).removeStickersSet(StickersActivity.this.getParentActivity(), stickerSet.set, !stickerSet.set.archived ? 1 : 2, StickersActivity.this, true);
                return;
            }
            if (which == 1) {
                MediaDataController.getInstance(StickersActivity.this.currentAccount).removeStickersSet(StickersActivity.this.getParentActivity(), stickerSet.set, 0, StickersActivity.this, true);
                return;
            }
            if (which == 2) {
                try {
                    Intent intent = new Intent("android.intent.action.SEND");
                    intent.setType("text/plain");
                    intent.putExtra("android.intent.extra.TEXT", String.format(Locale.US, DefaultWebClient.HTTPS_SCHEME + MessagesController.getInstance(StickersActivity.this.currentAccount).linkPrefix + "/addstickers/%s", stickerSet.set.short_name));
                    StickersActivity.this.getParentActivity().startActivityForResult(Intent.createChooser(intent, LocaleController.getString("StickersShare", R.string.StickersShare)), SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION);
                    return;
                } catch (Exception e) {
                    FileLog.e(e);
                    return;
                }
            }
            if (which == 3) {
                try {
                    ClipboardManager clipboard = (ClipboardManager) ApplicationLoader.applicationContext.getSystemService("clipboard");
                    ClipData clip = ClipData.newPlainText("label", String.format(Locale.US, DefaultWebClient.HTTPS_SCHEME + MessagesController.getInstance(StickersActivity.this.currentAccount).linkPrefix + "/addstickers/%s", stickerSet.set.short_name));
                    clipboard.setPrimaryClip(clip);
                    ToastUtils.show(R.string.LinkCopied);
                } catch (Exception e2) {
                    FileLog.e(e2);
                }
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            final int[] options;
            String[] rightTexts;
            int[] rightColors;
            int[] rightTextColors;
            String value;
            int itemViewType = holder.getItemViewType();
            if (itemViewType == 0) {
                SwipeLayout swipeLayout = (SwipeLayout) holder.itemView;
                swipeLayout.setItemWidth(AndroidUtilities.dp(80.0f));
                StickerSetCell stickerSetCell = (StickerSetCell) swipeLayout.getMainLayout();
                ArrayList<TLRPC.TL_messages_stickerSet> arrayList = MediaDataController.getInstance(StickersActivity.this.currentAccount).getStickerSets(StickersActivity.this.currentType);
                int row = position - StickersActivity.this.stickersStartRow;
                stickerSetCell.setStickersSet(arrayList.get(row), row != arrayList.size() + (-1));
                StickersActivity.this.sendReorder();
                final TLRPC.TL_messages_stickerSet stickerSet = stickerSetCell.getStickersSet();
                if (stickerSet != null && stickerSet.set != null && stickerSet.set.official) {
                    options = new int[]{0};
                    rightTexts = new String[]{LocaleController.getString("StickersRemove", R.string.StickersHide)};
                    rightColors = new int[]{-16540699};
                    rightTextColors = new int[]{-1};
                } else {
                    int[] rightTextColors2 = {3, 2, 1, 0};
                    options = rightTextColors2;
                    rightTexts = new String[]{LocaleController.getString("StickersCopy", R.string.StickersCopy), LocaleController.getString("StickersShare", R.string.StickersShare), LocaleController.getString("StickersRemove", R.string.StickersRemove), LocaleController.getString("StickersHide", R.string.StickersHide)};
                    rightColors = new int[]{-1250068, -28928, -2818048, -16540699};
                    rightTextColors = new int[]{-4539718, -1, -1, -1};
                }
                swipeLayout.setRightTexts(rightTexts);
                swipeLayout.setRightTextColors(rightTextColors);
                swipeLayout.setRightColors(rightColors);
                swipeLayout.setTextSize(AndroidUtilities.sp2px(14.0f));
                swipeLayout.rebuildLayout();
                swipeLayout.setOnSwipeItemClickListener(new SwipeLayout.OnSwipeItemClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$StickersActivity$ListAdapter$InNvy4raLuN8ScCOKcHsVvJz3FQ
                    @Override // im.uwrkaxlmjj.ui.hviews.slidemenu.SwipeLayout.OnSwipeItemClickListener
                    public final void onSwipeItemClick(boolean z, int i) {
                        this.f$0.lambda$onBindViewHolder$0$StickersActivity$ListAdapter(options, stickerSet, z, i);
                    }
                });
                if (StickersActivity.this.stickersEndRow - StickersActivity.this.stickersStartRow != 1) {
                    if (position != StickersActivity.this.stickersStartRow) {
                        if (position == StickersActivity.this.stickersEndRow - 1) {
                            holder.itemView.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                            return;
                        }
                        return;
                    }
                    holder.itemView.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f, Theme.getColor(Theme.key_windowBackgroundWhite)));
                    return;
                }
                holder.itemView.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                return;
            }
            if (itemViewType == 1) {
                if (position != StickersActivity.this.featuredInfoRow) {
                    if (position == StickersActivity.this.archivedInfoRow) {
                        if (StickersActivity.this.currentType == 0) {
                            ((TextInfoPrivacyCell) holder.itemView).setText(LocaleController.getString("ArchivedStickersInfo", R.string.ArchivedStickersInfo));
                        } else {
                            ((TextInfoPrivacyCell) holder.itemView).setText(LocaleController.getString("ArchivedMasksInfo", R.string.ArchivedMasksInfo));
                        }
                    } else if (position != StickersActivity.this.masksInfoRow) {
                        if (position != StickersActivity.this.loopInfoRow) {
                            if (position == StickersActivity.this.yourStickerBagInfoRow) {
                                ((TextInfoPrivacyCell) holder.itemView).setText(LocaleController.getString("YourStickerPackage", R.string.YourStickerPackage));
                            }
                        } else {
                            ((TextInfoPrivacyCell) holder.itemView).setText(LocaleController.getString("StickerLoopAnimatorPlay", R.string.StickerLoopAnimatorPlay));
                        }
                    } else {
                        ((TextInfoPrivacyCell) holder.itemView).setText(LocaleController.getString("MasksInfo", R.string.MasksInfo));
                    }
                } else {
                    String text = LocaleController.getString("FeaturedStickersInfo", R.string.FeaturedStickersInfo);
                    int index = text.indexOf("@stickers");
                    if (index != -1) {
                        try {
                            SpannableStringBuilder stringBuilder = new SpannableStringBuilder(text);
                            URLSpanNoUnderline spanNoUnderline = new URLSpanNoUnderline("@stickers") { // from class: im.uwrkaxlmjj.ui.StickersActivity.ListAdapter.1
                                @Override // im.uwrkaxlmjj.ui.components.URLSpanNoUnderline, android.text.style.URLSpan, android.text.style.ClickableSpan
                                public void onClick(View widget) {
                                    MessagesController.getInstance(StickersActivity.this.currentAccount).openByUserName("stickers", StickersActivity.this, 1);
                                }
                            };
                            stringBuilder.setSpan(spanNoUnderline, index, "@stickers".length() + index, 18);
                            ((TextInfoPrivacyCell) holder.itemView).setText(stringBuilder);
                        } catch (Exception e) {
                            FileLog.e(e);
                            ((TextInfoPrivacyCell) holder.itemView).setText(text);
                        }
                    } else {
                        ((TextInfoPrivacyCell) holder.itemView).setText(text);
                    }
                }
                holder.itemView.setClickable(true);
                holder.itemView.setFocusable(true);
                holder.itemView.setFocusableInTouchMode(true);
                return;
            }
            if (itemViewType != 2) {
                if (itemViewType == 4 && position == StickersActivity.this.loopRow) {
                    MryTextCheckCell cell = (MryTextCheckCell) holder.itemView;
                    cell.setTextAndCheck(LocaleController.getString("LoopAnimatedStickers", R.string.LoopAnimatedStickers), SharedConfig.loopStickers, false);
                    holder.itemView.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                    return;
                }
                return;
            }
            if (position == StickersActivity.this.featuredRow) {
                int count = MediaDataController.getInstance(StickersActivity.this.currentAccount).getUnreadStickerSets().size();
                ((TextSettingCell) holder.itemView).setTextAndValue(LocaleController.getString("FeaturedStickers", R.string.FeaturedStickers), count != 0 ? String.format("%d", Integer.valueOf(count)) : "", true, true);
                return;
            }
            if (position == StickersActivity.this.archivedRow) {
                if (StickersActivity.this.currentType == 0) {
                    ((TextSettingCell) holder.itemView).setText(LocaleController.getString("ArchivedStickers", R.string.ArchivedStickers), false);
                    return;
                } else {
                    ((TextSettingCell) holder.itemView).setText(LocaleController.getString("ArchivedMasks", R.string.ArchivedMasks), false);
                    return;
                }
            }
            if (position != StickersActivity.this.masksRow) {
                if (position == StickersActivity.this.suggestRow) {
                    int i = SharedConfig.suggestStickers;
                    if (i == 0) {
                        value = LocaleController.getString("SuggestStickersAll", R.string.SuggestStickersAll);
                    } else if (i == 1) {
                        value = LocaleController.getString("SuggestStickersInstalled", R.string.SuggestStickersInstalled);
                    } else {
                        value = LocaleController.getString("SuggestStickersNone", R.string.SuggestStickersNone);
                    }
                    ((TextSettingCell) holder.itemView).setTextAndValue(LocaleController.getString("SuggestStickers", R.string.SuggestStickers), value, true, true);
                    holder.itemView.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f, Theme.getColor(Theme.key_windowBackgroundWhite)));
                    return;
                }
                return;
            }
            ((TextSettingCell) holder.itemView).setText(LocaleController.getString("Masks", R.string.Masks), true, true);
        }

        public /* synthetic */ void lambda$onBindViewHolder$0$StickersActivity$ListAdapter(int[] options, TLRPC.TL_messages_stickerSet stickerSet, boolean left, int index) {
            processSelectionOption(options[index], stickerSet);
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            int type = holder.getItemViewType();
            return type == 0 || type == 2 || type == 4;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view = null;
            if (viewType == 0) {
                view = new SwipeLayout(this.mContext) { // from class: im.uwrkaxlmjj.ui.StickersActivity.ListAdapter.2
                    @Override // android.view.View
                    public boolean onTouchEvent(MotionEvent event) {
                        if (isExpanded()) {
                            return true;
                        }
                        return super.onTouchEvent(event);
                    }
                };
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                StickerSetCell stickerSetCell = new StickerSetCell(this.mContext, 0);
                ((SwipeLayout) view).setUpView(stickerSetCell);
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, -2));
            } else if (viewType == 1) {
                view = new TextInfoPrivacyCell(this.mContext);
            } else if (viewType == 2) {
                view = new TextSettingCell(this.mContext);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            } else if (viewType == 3) {
                view = new ShadowSectionCell(this.mContext);
            } else if (viewType == 4) {
                view = new MryTextCheckCell(this.mContext);
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            }
            view.setLayoutParams(new RecyclerView.LayoutParams(-1, -2));
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int i) {
            if (i >= StickersActivity.this.stickersStartRow && i < StickersActivity.this.stickersEndRow) {
                return 0;
            }
            if (i != StickersActivity.this.featuredInfoRow && i != StickersActivity.this.archivedInfoRow && i != StickersActivity.this.masksInfoRow && i != StickersActivity.this.loopInfoRow && i != StickersActivity.this.yourStickerBagInfoRow) {
                if (i != StickersActivity.this.featuredRow && i != StickersActivity.this.archivedRow && i != StickersActivity.this.masksRow && i != StickersActivity.this.suggestRow) {
                    if (i == StickersActivity.this.suggestInfoRow) {
                        return 3;
                    }
                    return i == StickersActivity.this.loopRow ? 4 : 0;
                }
                return 2;
            }
            return 1;
        }

        public void swapElements(int fromIndex, int toIndex) {
            if (fromIndex != toIndex) {
                StickersActivity.this.needReorder = true;
            }
            ArrayList<TLRPC.TL_messages_stickerSet> arrayList = MediaDataController.getInstance(StickersActivity.this.currentAccount).getStickerSets(StickersActivity.this.currentType);
            TLRPC.TL_messages_stickerSet from = arrayList.get(fromIndex - StickersActivity.this.stickersStartRow);
            arrayList.set(fromIndex - StickersActivity.this.stickersStartRow, arrayList.get(toIndex - StickersActivity.this.stickersStartRow));
            arrayList.set(toIndex - StickersActivity.this.stickersStartRow, from);
            notifyItemMoved(fromIndex, toIndex);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        return new ThemeDescription[]{new ThemeDescription(this.listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{StickerSetCell.class, TextSettingsCell.class, TextCheckCell.class}, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundGray), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.listView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector), new ThemeDescription(this.listView, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.listView, 0, new Class[]{View.class}, Theme.dividerPaint, null, null, Theme.key_divider), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_switchTrack), new ThemeDescription(this.listView, 0, new Class[]{TextCheckCell.class}, new String[]{"checkBox"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_switchTrackChecked), new ThemeDescription(this.listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{TextInfoPrivacyCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow), new ThemeDescription(this.listView, 0, new Class[]{TextInfoPrivacyCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText4), new ThemeDescription(this.listView, ThemeDescription.FLAG_LINKCOLOR, new Class[]{TextInfoPrivacyCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteLinkText), new ThemeDescription(this.listView, 0, new Class[]{TextSettingsCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{TextSettingsCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteValueText), new ThemeDescription(this.listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{ShadowSectionCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow), new ThemeDescription(this.listView, 0, new Class[]{StickerSetCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, 0, new Class[]{StickerSetCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText2), new ThemeDescription(this.listView, ThemeDescription.FLAG_USEBACKGROUNDDRAWABLE | ThemeDescription.FLAG_DRAWABLESELECTEDSTATE, new Class[]{StickerSetCell.class}, new String[]{"optionsButton"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_stickers_menuSelector), new ThemeDescription(this.listView, 0, new Class[]{StickerSetCell.class}, new String[]{"optionsButton"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_stickers_menu)};
    }
}
