package im.uwrkaxlmjj.ui.fragments.adapter;

import android.content.Context;
import android.content.SharedPreferences;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.DialogObject;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.SharedConfig;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.cell.FmtDialogCell;
import im.uwrkaxlmjj.ui.cells.DialogMeUrlCell;
import im.uwrkaxlmjj.ui.cells.DialogsEmptyCell;
import im.uwrkaxlmjj.ui.cells.EmptyCell;
import im.uwrkaxlmjj.ui.cells.HeaderCell;
import im.uwrkaxlmjj.ui.cells.LoadingCell;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.fragments.DialogsFragment;
import im.uwrkaxlmjj.ui.hviews.slidemenu.SwipeLayout;
import java.util.ArrayList;
import java.util.Collections;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class FmtDialogsAdapter extends RecyclerListView.SelectionAdapter {
    private ArrayList<Long> allDialogIdsList;
    private int currentCount;
    private int dCount;
    private FmtDialogDelegate delegate;
    private boolean dialogsListFrozen;
    private int dialogsType;
    private int folderId;
    private boolean hasHints;
    private boolean isEdit;
    private boolean isReordering;
    private Context mContext;
    private long openedDialogId;
    private int currentAccount = UserConfig.selectedAccount;
    private ArrayList<Long> selectedDialogs = new ArrayList<>();

    public interface FmtDialogDelegate {
        void onItemMenuClick(boolean z, int i, long j, int i2);
    }

    public void setEdit(boolean edit) {
        this.isEdit = edit;
    }

    public void setDelegate(FmtDialogDelegate delegate) {
        this.delegate = delegate;
    }

    public FmtDialogsAdapter(Context context, int dialogsType, int folder) {
        this.mContext = context;
        this.folderId = folder;
        this.dialogsType = dialogsType;
    }

    public void setDialogsType(int type) {
        this.dialogsType = type;
    }

    public void setOpenedDialogId(long id) {
        this.openedDialogId = id;
    }

    public boolean addOrRemoveSelectedDialog(long did, View cell) {
        if (this.selectedDialogs.contains(Long.valueOf(did))) {
            this.selectedDialogs.remove(Long.valueOf(did));
            if (cell instanceof FmtDialogCell) {
                ((FmtDialogCell) cell).setChecked(false, true);
            }
            return false;
        }
        this.selectedDialogs.add(Long.valueOf(did));
        if (cell instanceof FmtDialogCell) {
            ((FmtDialogCell) cell).setChecked(true, true);
        }
        return true;
    }

    public ArrayList<Long> getSelectedDialogs() {
        return this.selectedDialogs;
    }

    public ArrayList<Long> getAllDialogIdsList() {
        ArrayList<Long> arrayList = this.allDialogIdsList;
        if (arrayList == null) {
            this.allDialogIdsList = new ArrayList<>();
        } else {
            arrayList.clear();
        }
        ArrayList<TLRPC.Dialog> arrayList2 = DialogsFragment.getDialogsArray(this.currentAccount, this.dialogsType, 0, this.dialogsListFrozen);
        int i = 0;
        while (i < getItemCount()) {
            boolean loopNetIndex = false;
            if (this.hasHints) {
                int count = MessagesController.getInstance(this.currentAccount).hintDialogs.size();
                if (i < count + 2) {
                    this.allDialogIdsList.add(Long.valueOf(MessagesController.getInstance(this.currentAccount).hintDialogs.get(i - 1).chat_id));
                    loopNetIndex = true;
                } else {
                    i -= count + 2;
                }
            }
            if (!loopNetIndex && i >= 0 && i < arrayList2.size()) {
                this.allDialogIdsList.add(Long.valueOf(arrayList2.get(i).id));
            }
            i++;
        }
        return this.allDialogIdsList;
    }

    public void onReorderStateChanged(boolean reordering) {
        this.isReordering = reordering;
    }

    public int fixPosition(int position) {
        if (this.hasHints) {
            return position - (MessagesController.getInstance(this.currentAccount).hintDialogs.size() + 2);
        }
        return position;
    }

    public boolean isDataSetChanged() {
        int current = this.currentCount;
        int currentDialogsCount = this.dCount;
        return (current == getItemCount() && currentDialogsCount == this.dCount && current != 1) ? false : true;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemCount() {
        ArrayList<TLRPC.Dialog> array = DialogsFragment.getDialogsArray(this.currentAccount, this.dialogsType, 0, this.dialogsListFrozen);
        int dialogsCount = array.size();
        this.dCount = dialogsCount;
        if (dialogsCount == 0 && MessagesController.getInstance(this.currentAccount).isLoadingDialogs(0)) {
            this.currentCount = 0;
            return 0;
        }
        int count = dialogsCount;
        if (!MessagesController.getInstance(this.currentAccount).isDialogsEndReached(0) || dialogsCount == 0) {
            count++;
        }
        if (this.hasHints) {
            count += MessagesController.getInstance(this.currentAccount).hintDialogs.size() + 2;
        } else if (dialogsCount == 0 && ContactsController.getInstance(this.currentAccount).contacts.isEmpty() && ContactsController.getInstance(this.currentAccount).isLoadingContacts()) {
            this.currentCount = 0;
            return 0;
        }
        this.currentCount = count;
        return count;
    }

    public TLObject getItem(int i) {
        ArrayList<TLRPC.Dialog> arrayList = DialogsFragment.getDialogsArray(this.currentAccount, this.dialogsType, 0, this.dialogsListFrozen);
        if (this.hasHints) {
            int count = MessagesController.getInstance(this.currentAccount).hintDialogs.size();
            if (i < count + 2) {
                return MessagesController.getInstance(this.currentAccount).hintDialogs.get(i - 1);
            }
            i -= count + 2;
        }
        if (i < 0 || i >= arrayList.size()) {
            return null;
        }
        return arrayList.get(i);
    }

    public void setDialogsListFrozen(boolean frozen) {
        this.dialogsListFrozen = frozen;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public void notifyDataSetChanged() {
        this.hasHints = !MessagesController.getInstance(this.currentAccount).hintDialogs.isEmpty();
        super.notifyDataSetChanged();
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public void onViewAttachedToWindow(RecyclerView.ViewHolder holder) {
        if (holder.itemView instanceof SwipeLayout) {
            SwipeLayout swipeLayout = (SwipeLayout) holder.itemView;
            FmtDialogCell dialogCell = (FmtDialogCell) swipeLayout.getMainLayout();
            dialogCell.onReorderStateChanged(this.isReordering, false);
            int position = fixPosition(holder.getAdapterPosition());
            dialogCell.setDialogIndex(position);
            dialogCell.checkCurrentDialogIndex(this.dialogsListFrozen);
            dialogCell.setChecked(this.selectedDialogs.contains(Long.valueOf(dialogCell.getDialogId())), false);
        }
    }

    public boolean hasSelectedDialogs() {
        ArrayList<Long> arrayList = this.selectedDialogs;
        return (arrayList == null || arrayList.isEmpty()) ? false : true;
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
    public boolean isEnabled(RecyclerView.ViewHolder holder) {
        int viewType = holder.getItemViewType();
        return (viewType == 1 || viewType == 5 || viewType == 3 || viewType == 8 || viewType == 7 || viewType == 9 || viewType == 10) ? false : true;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup viewGroup, int viewType) {
        View view;
        if (viewType == 0) {
            view = new SwipeLayout(this.mContext) { // from class: im.uwrkaxlmjj.ui.fragments.adapter.FmtDialogsAdapter.1
                @Override // android.view.View
                public boolean onTouchEvent(MotionEvent event) {
                    if (isExpanded()) {
                        return true;
                    }
                    return super.onTouchEvent(event);
                }
            };
            ((ViewGroup) view).setClipChildren(false);
            FmtDialogCell dialogCell = new FmtDialogCell(this.mContext, false);
            SwipeLayout swipeLayout = (SwipeLayout) view;
            swipeLayout.setUpView(dialogCell);
            view.setLayoutParams(new RecyclerView.LayoutParams(-1, -2));
        } else if (viewType != 1) {
            if (viewType == 2) {
                HeaderCell headerCell = new HeaderCell(this.mContext);
                headerCell.setText(LocaleController.getString("RecentlyViewed", R.string.RecentlyViewed));
                TextView textView = new TextView(this.mContext);
                textView.setTextSize(1, 15.0f);
                textView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
                textView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueHeader));
                textView.setText(LocaleController.getString("RecentlyViewedHide", R.string.RecentlyViewedHide));
                textView.setGravity((LocaleController.isRTL ? 3 : 5) | 16);
                headerCell.addView(textView, LayoutHelper.createFrame(-1.0f, -1.0f, (LocaleController.isRTL ? 3 : 5) | 48, 17.0f, 15.0f, 17.0f, 0.0f));
                textView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.fragments.adapter.-$$Lambda$FmtDialogsAdapter$UysBnjsPtdtheeldq_NEvM7J52Y
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view2) {
                        this.f$0.lambda$onCreateViewHolder$0$FmtDialogsAdapter(view2);
                    }
                });
                view = headerCell;
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, viewType == 5 ? -1 : -2));
            } else if (viewType == 3) {
                FrameLayout frameLayout = new FrameLayout(this.mContext) { // from class: im.uwrkaxlmjj.ui.fragments.adapter.FmtDialogsAdapter.2
                    @Override // android.widget.FrameLayout, android.view.View
                    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                        super.onMeasure(View.MeasureSpec.makeMeasureSpec(View.MeasureSpec.getSize(widthMeasureSpec), 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(12.0f), 1073741824));
                    }
                };
                frameLayout.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
                View v = new View(this.mContext);
                v.setBackgroundDrawable(Theme.getThemedDrawable(this.mContext, R.drawable.greydivider, Theme.key_windowBackgroundGrayShadow));
                frameLayout.addView(v, LayoutHelper.createFrame(-1, -1.0f));
                frameLayout.setLayoutParams(new RecyclerView.LayoutParams(-1, viewType == 5 ? -1 : -2));
                view = frameLayout;
            } else if (viewType == 4) {
                view = new DialogMeUrlCell(this.mContext);
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, viewType == 5 ? -1 : -2));
            } else if (viewType == 5) {
                view = new DialogsEmptyCell(this.mContext);
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, viewType == 5 ? -1 : -2));
            } else if (viewType != 11) {
                view = new View(this.mContext) { // from class: im.uwrkaxlmjj.ui.fragments.adapter.FmtDialogsAdapter.3
                    @Override // android.view.View
                    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                        int height;
                        View parent;
                        int size = DialogsFragment.getDialogsArray(FmtDialogsAdapter.this.currentAccount, FmtDialogsAdapter.this.dialogsType, 0, FmtDialogsAdapter.this.dialogsListFrozen).size();
                        boolean hasArchive = MessagesController.getInstance(FmtDialogsAdapter.this.currentAccount).dialogs_dict.get(DialogObject.makeFolderDialogId(1)) != null;
                        if (size == 0 || !hasArchive) {
                            height = 0;
                        } else {
                            int height2 = View.MeasureSpec.getSize(heightMeasureSpec);
                            if (height2 == 0 && (parent = (View) getParent()) != null) {
                                height2 = parent.getMeasuredHeight();
                            }
                            if (height2 == 0) {
                                height2 = (AndroidUtilities.displaySize.y - ActionBar.getCurrentActionBarHeight()) - (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0);
                            }
                            int cellHeight = AndroidUtilities.dp(SharedConfig.useThreeLinesLayout ? 68.0f : 62.0f);
                            int dialogsHeight = (size * cellHeight) + (size - 1);
                            if (dialogsHeight < height2) {
                                height = (height2 - dialogsHeight) + cellHeight + 1;
                            } else if (dialogsHeight - height2 < cellHeight + 1) {
                                height = (cellHeight + 1) - (dialogsHeight - height2);
                            } else {
                                height = 0;
                            }
                        }
                        setMeasuredDimension(View.MeasureSpec.getSize(widthMeasureSpec), height);
                    }
                };
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, viewType == 5 ? -1 : -2));
            } else {
                view = new EmptyCell(this.mContext, AndroidUtilities.dp(46.0f));
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, viewType == 5 ? -1 : -2));
            }
        } else {
            view = new LoadingCell(this.mContext);
            view.setLayoutParams(new RecyclerView.LayoutParams(-1, viewType == 5 ? -1 : -2));
        }
        return new RecyclerListView.Holder(view);
    }

    public /* synthetic */ void lambda$onCreateViewHolder$0$FmtDialogsAdapter(View view1) {
        MessagesController.getInstance(this.currentAccount).hintDialogs.clear();
        SharedPreferences preferences = MessagesController.getGlobalMainSettings();
        preferences.edit().remove("installReferer").commit();
        notifyDataSetChanged();
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public void onBindViewHolder(RecyclerView.ViewHolder holder, final int i) {
        Drawable bg;
        int itemViewType = holder.getItemViewType();
        if (itemViewType != 0) {
            if (itemViewType == 4) {
                ((DialogMeUrlCell) holder.itemView).setRecentMeUrl((TLRPC.RecentMeUrl) getItem(i));
                return;
            }
            return;
        }
        SwipeLayout swipeLayout = (SwipeLayout) holder.itemView;
        swipeLayout.setItemWidth(AndroidUtilities.dp(65.0f));
        FmtDialogCell cell = (FmtDialogCell) swipeLayout.getMainLayout();
        cell.setCheckBoxVisible(this.isEdit, true, i);
        int radius = AndroidUtilities.dp(5.0f);
        if (getItemCount() == 1) {
            bg = Theme.createRoundRectDrawable(radius, Theme.getColor(Theme.key_windowBackgroundWhite));
        } else if (i == 0 || i == getItemCount() - 1) {
            bg = i == 0 ? Theme.createRoundRectDrawable(radius, radius, 0.0f, 0.0f, Theme.getColor(Theme.key_windowBackgroundWhite)) : Theme.createRoundRectDrawable(0.0f, 0.0f, radius, radius, Theme.getColor(Theme.key_windowBackgroundWhite));
        } else {
            bg = new ColorDrawable(Theme.getColor(Theme.key_windowBackgroundWhite));
        }
        swipeLayout.setBackground(this.isEdit ? bg : null);
        cell.setBackground(bg);
        TLRPC.Dialog dialog = (TLRPC.Dialog) getItem(i);
        int lower_id = (int) dialog.id;
        int high_id = (int) (dialog.id >> 32);
        if (lower_id >= 0 || high_id != 1) {
        }
        int[] leftColors = {Theme.getColor(Theme.key_neutralWeak), Theme.getColor(Theme.key_accentSuccess)};
        int[] leftIcons = new int[2];
        leftIcons[0] = dialog.unread_count != 0 ? R.drawable.msg_markread : R.drawable.msg_markunread;
        leftIcons[1] = dialog.pinned ? R.drawable.msg_unpin : R.drawable.msg_pin;
        int[] leftIconColors = {-1, -1};
        String[] leftTexts = new String[2];
        leftTexts[0] = LocaleController.getString(dialog.unread_count != 0 ? R.string.MarkAsRead : R.string.MarkAsUnread);
        leftTexts[1] = LocaleController.getString(dialog.pinned ? R.string.UnpinFromTop : R.string.PinToTop);
        int[] leftTextColors = {-1, -1};
        int[] rightColors = {Theme.getColor(Theme.key_accentOrange), Theme.getColor(Theme.key_accentError)};
        int[] rightIcons = new int[2];
        rightIcons[0] = MessagesController.getInstance(UserConfig.selectedAccount).isDialogMuted(dialog.id) ? R.drawable.msg_unmute : R.drawable.msg_mute;
        rightIcons[1] = R.drawable.msg_delete;
        int[] rightIconColors = {-1, -1};
        String[] rightTexts = new String[2];
        rightTexts[0] = LocaleController.getString(MessagesController.getInstance(UserConfig.selectedAccount).isDialogMuted(dialog.id) ? R.string.ChatsUnmute : R.string.ChatsMute);
        rightTexts[1] = LocaleController.getString(R.string.Delete);
        int[] rightTextColors = {-1, -1};
        swipeLayout.setLeftIcons(leftIcons);
        swipeLayout.setLeftIconColors(leftIconColors);
        swipeLayout.setLeftTexts(leftTexts);
        swipeLayout.setLeftTextColors(leftTextColors);
        swipeLayout.setLeftColors(leftColors);
        swipeLayout.setRightIcons(rightIcons);
        swipeLayout.setRightIconColors(rightIconColors);
        swipeLayout.setRightTexts(rightTexts);
        swipeLayout.setRightTextColors(rightTextColors);
        swipeLayout.setRightColors(rightColors);
        swipeLayout.setCanFullSwipeFromRight(true);
        swipeLayout.setCanFullSwipeFromLeft(true);
        swipeLayout.setIconSize(AndroidUtilities.dp(24.0f));
        swipeLayout.setTextSize(AndroidUtilities.sp2px(12.0f));
        swipeLayout.setAutoHideSwipe(true);
        swipeLayout.setOnlyOneSwipe(true);
        swipeLayout.rebuildLayout();
        swipeLayout.setOnSwipeItemClickListener(new SwipeLayout.OnSwipeItemClickListener() { // from class: im.uwrkaxlmjj.ui.fragments.adapter.-$$Lambda$FmtDialogsAdapter$6DpxODzg2KEluvL3KRHXpqe9LZ0
            @Override // im.uwrkaxlmjj.ui.hviews.slidemenu.SwipeLayout.OnSwipeItemClickListener
            public final void onSwipeItemClick(boolean z, int i2) {
                this.f$0.lambda$onBindViewHolder$1$FmtDialogsAdapter(i, z, i2);
            }
        });
        TLRPC.Dialog nextDialog = (TLRPC.Dialog) getItem(i + 1);
        cell.useSeparator = i != getItemCount() + (-1);
        cell.fullSeparator = (!dialog.pinned || nextDialog == null || nextDialog.pinned) ? false : true;
        if (AndroidUtilities.isTablet()) {
            cell.setDialogSelected(dialog.id == this.openedDialogId);
        }
        cell.setChecked(this.selectedDialogs.contains(Long.valueOf(dialog.id)), false);
        cell.setDialog(dialog, this.dialogsType, 0);
    }

    public /* synthetic */ void lambda$onBindViewHolder$1$FmtDialogsAdapter(int i, boolean left, int index) {
        if (this.delegate != null) {
            TLRPC.Dialog item = (TLRPC.Dialog) getItem(i);
            this.delegate.onItemMenuClick(left, index, item.id, i);
        }
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemViewType(int i) {
        if (this.hasHints) {
            int count = MessagesController.getInstance(this.currentAccount).hintDialogs.size();
            if (i < count + 2) {
                if (i == 0) {
                    return 2;
                }
                if (i == count + 1) {
                    return 3;
                }
                return 4;
            }
            i -= count + 2;
        }
        int size = DialogsFragment.getDialogsArray(this.currentAccount, this.dialogsType, 0, this.dialogsListFrozen).size();
        if (i != size) {
            return i > size ? 10 : 0;
        }
        if (!MessagesController.getInstance(this.currentAccount).isDialogsEndReached(0)) {
            return 1;
        }
        if (size != 0) {
            return 10;
        }
        return 5;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public void notifyItemMoved(int fromPosition, int toPosition) {
        ArrayList<TLRPC.Dialog> dialogs = DialogsFragment.getDialogsArray(this.currentAccount, this.dialogsType, 0, false);
        int fromIndex = fixPosition(fromPosition);
        int toIndex = fixPosition(toPosition);
        TLRPC.Dialog fromDialog = dialogs.get(fromIndex);
        TLRPC.Dialog toDialog = dialogs.get(toIndex);
        int oldNum = fromDialog.pinnedNum;
        fromDialog.pinnedNum = toDialog.pinnedNum;
        toDialog.pinnedNum = oldNum;
        Collections.swap(dialogs, fromIndex, toIndex);
        super.notifyItemMoved(fromPosition, toPosition);
    }
}
