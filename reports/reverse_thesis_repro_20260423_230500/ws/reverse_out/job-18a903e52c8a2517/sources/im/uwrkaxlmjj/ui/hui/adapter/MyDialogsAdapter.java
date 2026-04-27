package im.uwrkaxlmjj.ui.hui.adapter;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.SystemClock;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewpager.widget.ViewPager;
import com.google.android.exoplayer2.trackselection.AdaptiveTrackSelection;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.DialogObject;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.SharedConfig;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.DialogsActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.cells.ArchiveHintCell;
import im.uwrkaxlmjj.ui.cells.DialogCell;
import im.uwrkaxlmjj.ui.cells.DialogMeUrlCell;
import im.uwrkaxlmjj.ui.cells.HeaderCell;
import im.uwrkaxlmjj.ui.cells.LoadingCell;
import im.uwrkaxlmjj.ui.cells.ShadowSectionCell;
import im.uwrkaxlmjj.ui.cells.UserCell;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.hcells.MyDialogsEmptyCell;
import im.uwrkaxlmjj.ui.hviews.slidemenu.SwipeLayout;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class MyDialogsAdapter extends RecyclerListView.SelectionAdapter {
    private ArchiveHintCell archiveHintCell;
    private int currentAccount = UserConfig.selectedAccount;
    private int currentCount;
    private boolean dialogsListFrozen;
    private int dialogsType;
    private int folderId;
    private boolean hasHints;
    private boolean isEdit;
    private boolean isOnlySelect;
    private boolean isReordering;
    private long lastSortTime;
    private Context mContext;
    private ArrayList<TLRPC.Contact> onlineContacts;
    private long openedDialogId;
    private int prevContactsCount;
    private ArrayList<Long> selectedDialogs;
    private boolean showArchiveHint;

    public void setEdit(boolean edit) {
        this.isEdit = edit;
    }

    public MyDialogsAdapter(Context context, int type, int folder, boolean onlySelect) {
        this.mContext = context;
        this.dialogsType = type;
        this.folderId = folder;
        this.isOnlySelect = onlySelect;
        this.hasHints = folder == 0 && type == 0 && !onlySelect;
        this.selectedDialogs = new ArrayList<>();
        if (this.folderId == 1) {
            SharedPreferences preferences = MessagesController.getGlobalMainSettings();
            this.showArchiveHint = preferences.getBoolean("archivehint", true);
            preferences.edit().putBoolean("archivehint", false).commit();
            if (this.showArchiveHint) {
                this.archiveHintCell = new ArchiveHintCell(context);
            }
        }
    }

    public void setOpenedDialogId(long id) {
        this.openedDialogId = id;
    }

    public boolean hasSelectedDialogs() {
        ArrayList<Long> arrayList = this.selectedDialogs;
        return (arrayList == null || arrayList.isEmpty()) ? false : true;
    }

    public boolean addOrRemoveSelectedDialog(long did, View cell) {
        if (this.selectedDialogs.contains(Long.valueOf(did))) {
            this.selectedDialogs.remove(Long.valueOf(did));
            if (cell instanceof DialogCell) {
                ((DialogCell) cell).setChecked(false, true);
            }
            notifyDataSetChanged();
            return false;
        }
        this.selectedDialogs.add(Long.valueOf(did));
        if (cell instanceof DialogCell) {
            ((DialogCell) cell).setChecked(true, true);
        }
        notifyDataSetChanged();
        return true;
    }

    public ArrayList<Long> getSelectedDialogs() {
        return this.selectedDialogs;
    }

    public void onReorderStateChanged(boolean reordering) {
        this.isReordering = reordering;
    }

    public int fixPosition(int position) {
        if (this.hasHints) {
            position -= MessagesController.getInstance(this.currentAccount).hintDialogs.size() + 2;
        }
        if (this.showArchiveHint) {
            return position - 2;
        }
        return position;
    }

    public boolean isDataSetChanged() {
        int current = this.currentCount;
        return current != getItemCount() || current == 1;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemCount() {
        ArrayList<TLRPC.Dialog> array = DialogsActivity.getDialogsArray(this.currentAccount, this.dialogsType, this.folderId, this.dialogsListFrozen);
        int dialogsCount = array.size();
        if (dialogsCount == 0 && (this.folderId != 0 || MessagesController.getInstance(this.currentAccount).isLoadingDialogs(this.folderId))) {
            this.onlineContacts = null;
            if (this.folderId == 1 && this.showArchiveHint) {
                this.currentCount = 2;
                return 2;
            }
            this.currentCount = 0;
            return 0;
        }
        int count = dialogsCount;
        if (!MessagesController.getInstance(this.currentAccount).isDialogsEndReached(this.folderId) || dialogsCount == 0) {
            count++;
        }
        boolean hasContacts = false;
        if (this.hasHints) {
            count += MessagesController.getInstance(this.currentAccount).hintDialogs.size() + 2;
        } else if (this.dialogsType == 0 && dialogsCount == 0 && this.folderId == 0) {
            if (ContactsController.getInstance(this.currentAccount).contacts.isEmpty() && ContactsController.getInstance(this.currentAccount).isLoadingContacts()) {
                this.onlineContacts = null;
                this.currentCount = 0;
                return 0;
            }
            if (!ContactsController.getInstance(this.currentAccount).contacts.isEmpty()) {
                if (this.onlineContacts == null || this.prevContactsCount != ContactsController.getInstance(this.currentAccount).contacts.size()) {
                    ArrayList<TLRPC.Contact> arrayList = new ArrayList<>(ContactsController.getInstance(this.currentAccount).contacts);
                    this.onlineContacts = arrayList;
                    this.prevContactsCount = arrayList.size();
                    int selfId = UserConfig.getInstance(this.currentAccount).clientUserId;
                    int a = 0;
                    int N = this.onlineContacts.size();
                    while (true) {
                        if (a >= N) {
                            break;
                        }
                        if (this.onlineContacts.get(a).user_id != selfId) {
                            a++;
                        } else {
                            this.onlineContacts.remove(a);
                            break;
                        }
                    }
                    sortOnlineContacts(false);
                }
                count += this.onlineContacts.size() + 2;
                hasContacts = true;
            }
        }
        if (!hasContacts && this.onlineContacts != null) {
            this.onlineContacts = null;
        }
        if (this.folderId == 1 && this.showArchiveHint) {
            count += 2;
        }
        if (this.folderId == 0 && dialogsCount != 0) {
            count++;
        }
        this.currentCount = count;
        return count;
    }

    public TLObject getItem(int i) {
        ArrayList<TLRPC.Contact> arrayList = this.onlineContacts;
        if (arrayList != null) {
            int i2 = i - 3;
            if (i2 < 0 || i2 >= arrayList.size()) {
                return null;
            }
            return MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(this.onlineContacts.get(i2).user_id));
        }
        if (this.showArchiveHint) {
            i -= 2;
        }
        ArrayList<TLRPC.Dialog> arrayList2 = DialogsActivity.getDialogsArray(this.currentAccount, this.dialogsType, this.folderId, this.dialogsListFrozen);
        if (this.hasHints) {
            int count = MessagesController.getInstance(this.currentAccount).hintDialogs.size();
            if (i < count + 2) {
                return MessagesController.getInstance(this.currentAccount).hintDialogs.get(i - 1);
            }
            i -= count + 2;
        }
        if (i < 0 || i >= arrayList2.size()) {
            return null;
        }
        return arrayList2.get(i);
    }

    public void sortOnlineContacts(boolean notify) {
        if (this.onlineContacts != null) {
            if (notify && SystemClock.uptimeMillis() - this.lastSortTime < AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS) {
                return;
            }
            this.lastSortTime = SystemClock.uptimeMillis();
            try {
                final int currentTime = ConnectionsManager.getInstance(this.currentAccount).getCurrentTime();
                final MessagesController messagesController = MessagesController.getInstance(this.currentAccount);
                Collections.sort(this.onlineContacts, new Comparator() { // from class: im.uwrkaxlmjj.ui.hui.adapter.-$$Lambda$MyDialogsAdapter$XMP5oikEks4inIkccnCj3fN_Am4
                    @Override // java.util.Comparator
                    public final int compare(Object obj, Object obj2) {
                        return MyDialogsAdapter.lambda$sortOnlineContacts$0(messagesController, currentTime, (TLRPC.Contact) obj, (TLRPC.Contact) obj2);
                    }
                });
                if (notify) {
                    notifyDataSetChanged();
                }
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
    }

    static /* synthetic */ int lambda$sortOnlineContacts$0(MessagesController messagesController, int currentTime, TLRPC.Contact o1, TLRPC.Contact o2) {
        TLRPC.User user1 = messagesController.getUser(Integer.valueOf(o2.user_id));
        TLRPC.User user2 = messagesController.getUser(Integer.valueOf(o1.user_id));
        int status1 = 0;
        int status2 = 0;
        if (user1 != null) {
            if (user1.self) {
                status1 = currentTime + 50000;
            } else if (user1.status != null) {
                status1 = user1.status.expires;
            }
        }
        if (user2 != null) {
            if (user2.self) {
                status2 = currentTime + 50000;
            } else if (user2.status != null) {
                status2 = user2.status.expires;
            }
        }
        if (status1 > 0 && status2 > 0) {
            if (status1 > status2) {
                return 1;
            }
            return status1 < status2 ? -1 : 0;
        }
        if (status1 < 0 && status2 < 0) {
            if (status1 > status2) {
                return 1;
            }
            return status1 < status2 ? -1 : 0;
        }
        if ((status1 >= 0 || status2 <= 0) && (status1 != 0 || status2 == 0)) {
            return ((status2 >= 0 || status1 <= 0) && (status2 != 0 || status1 == 0)) ? 0 : 1;
        }
        return -1;
    }

    public void setDialogsListFrozen(boolean frozen) {
        this.dialogsListFrozen = frozen;
    }

    public ViewPager getArchiveHintCellPager() {
        ArchiveHintCell archiveHintCell = this.archiveHintCell;
        if (archiveHintCell != null) {
            return archiveHintCell.getViewPager();
        }
        return null;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public void notifyDataSetChanged() {
        this.hasHints = this.folderId == 0 && this.dialogsType == 0 && !this.isOnlySelect && !MessagesController.getInstance(this.currentAccount).hintDialogs.isEmpty();
        super.notifyDataSetChanged();
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public void onViewAttachedToWindow(RecyclerView.ViewHolder holder) {
        if (holder.itemView instanceof DialogCell) {
            DialogCell dialogCell = (DialogCell) holder.itemView;
            dialogCell.onReorderStateChanged(this.isReordering, false);
            int position = fixPosition(holder.getAdapterPosition());
            dialogCell.setDialogIndex(position);
            dialogCell.checkCurrentDialogIndex(this.dialogsListFrozen);
            dialogCell.setChecked(this.selectedDialogs.contains(Long.valueOf(dialogCell.getDialogId())), false);
        }
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
    public boolean isEnabled(RecyclerView.ViewHolder holder) {
        int viewType = holder.getItemViewType();
        return (viewType == 1 || viewType == 5 || viewType == 3 || viewType == 8 || viewType == 7 || viewType == 9 || viewType == 10) ? false : true;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup viewGroup, int i) {
        View userCell;
        switch (i) {
            case 0:
                SwipeLayout swipeLayout = new SwipeLayout(this.mContext) { // from class: im.uwrkaxlmjj.ui.hui.adapter.MyDialogsAdapter.1
                    @Override // android.view.View
                    public boolean onTouchEvent(MotionEvent event) {
                        if (isExpanded()) {
                            return true;
                        }
                        return super.onTouchEvent(event);
                    }
                };
                swipeLayout.setClipChildren(false);
                DialogCell dialogCell = new DialogCell(this.mContext, false);
                SwipeLayout swipeLayout2 = swipeLayout;
                swipeLayout2.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                swipeLayout2.setUpView(dialogCell);
                swipeLayout.setLayoutParams(new RecyclerView.LayoutParams(-1, -2));
                userCell = swipeLayout;
                break;
            case 1:
                userCell = new LoadingCell(this.mContext);
                break;
            case 2:
                HeaderCell headerCell = new HeaderCell(this.mContext);
                headerCell.setText(LocaleController.getString("RecentlyViewed", R.string.RecentlyViewed));
                TextView textView = new TextView(this.mContext);
                textView.setTextSize(1, 15.0f);
                textView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
                textView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueHeader));
                textView.setText(LocaleController.getString("RecentlyViewedHide", R.string.RecentlyViewedHide));
                textView.setGravity((LocaleController.isRTL ? 3 : 5) | 16);
                headerCell.addView(textView, LayoutHelper.createFrame(-1.0f, -1.0f, (LocaleController.isRTL ? 3 : 5) | 48, 17.0f, 15.0f, 17.0f, 0.0f));
                textView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.adapter.-$$Lambda$MyDialogsAdapter$BGdp-Z8jq6_R-6OCSC_KBxip5aM
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view) {
                        this.f$0.lambda$onCreateViewHolder$1$MyDialogsAdapter(view);
                    }
                });
                userCell = headerCell;
                break;
            case 3:
                FrameLayout frameLayout = new FrameLayout(this.mContext) { // from class: im.uwrkaxlmjj.ui.hui.adapter.MyDialogsAdapter.2
                    @Override // android.widget.FrameLayout, android.view.View
                    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                        super.onMeasure(View.MeasureSpec.makeMeasureSpec(View.MeasureSpec.getSize(widthMeasureSpec), 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(12.0f), 1073741824));
                    }
                };
                frameLayout.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
                frameLayout.addView(new View(this.mContext), LayoutHelper.createFrame(-1, -1.0f));
                userCell = frameLayout;
                break;
            case 4:
                userCell = new DialogMeUrlCell(this.mContext);
                break;
            case 5:
                userCell = new MyDialogsEmptyCell(this.mContext);
                break;
            case 6:
                userCell = new UserCell(this.mContext, 8, 0, false);
                break;
            case 7:
                HeaderCell headerCell2 = new HeaderCell(this.mContext);
                headerCell2.setText(LocaleController.getString("YourContacts", R.string.YourContacts));
                userCell = headerCell2;
                break;
            case 8:
                userCell = new ShadowSectionCell(this.mContext);
                break;
            case 9:
                ArchiveHintCell archiveHintCell = this.archiveHintCell;
                userCell = archiveHintCell;
                if (this.archiveHintCell.getParent() != null) {
                    ((ViewGroup) this.archiveHintCell.getParent()).removeView(this.archiveHintCell);
                    userCell = archiveHintCell;
                }
                break;
            default:
                userCell = new View(this.mContext) { // from class: im.uwrkaxlmjj.ui.hui.adapter.MyDialogsAdapter.3
                    @Override // android.view.View
                    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                        int height;
                        View parent;
                        int size = DialogsActivity.getDialogsArray(MyDialogsAdapter.this.currentAccount, MyDialogsAdapter.this.dialogsType, MyDialogsAdapter.this.folderId, MyDialogsAdapter.this.dialogsListFrozen).size();
                        boolean hasArchive = MessagesController.getInstance(MyDialogsAdapter.this.currentAccount).dialogs_dict.get(DialogObject.makeFolderDialogId(1)) != null;
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
                            int cellHeight = AndroidUtilities.dp(SharedConfig.useThreeLinesLayout ? 78.0f : 72.0f);
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
                break;
        }
        userCell.setLayoutParams(new RecyclerView.LayoutParams(-1, i == 5 ? -1 : -2));
        return new RecyclerListView.Holder(userCell);
    }

    public /* synthetic */ void lambda$onCreateViewHolder$1$MyDialogsAdapter(View view1) {
        MessagesController.getInstance(this.currentAccount).hintDialogs.clear();
        SharedPreferences preferences = MessagesController.getGlobalMainSettings();
        preferences.edit().remove("installReferer").commit();
        notifyDataSetChanged();
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public void onBindViewHolder(RecyclerView.ViewHolder holder, int i) {
        int itemViewType = holder.getItemViewType();
        if (itemViewType != 0) {
            if (itemViewType == 4) {
                ((DialogMeUrlCell) holder.itemView).setRecentMeUrl((TLRPC.RecentMeUrl) getItem(i));
                return;
            }
            if (itemViewType == 5) {
                ((MyDialogsEmptyCell) holder.itemView).setType(this.dialogsType);
                return;
            } else {
                if (itemViewType == 6) {
                    UserCell cell = (UserCell) holder.itemView;
                    TLRPC.User user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(this.onlineContacts.get(i - 3).user_id));
                    cell.setData(user, null, null, 0);
                    return;
                }
                return;
            }
        }
        SwipeLayout swipeLayout = (SwipeLayout) holder.itemView;
        DialogCell cell2 = (DialogCell) swipeLayout.getMainLayout();
        TLRPC.Dialog dialog = (TLRPC.Dialog) getItem(i);
        TLRPC.Dialog nextDialog = (TLRPC.Dialog) getItem(i + 1);
        cell2.setCheckBoxVisible(this.isEdit, true, i);
        if (this.folderId == 0) {
            cell2.useSeparator = i != getItemCount() - 2;
            if (getItemCount() == 2) {
                swipeLayout.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
            } else if (i == 0) {
                swipeLayout.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f, Theme.getColor(Theme.key_windowBackgroundWhite)));
            } else if (i == getItemCount() - 2) {
                swipeLayout.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
            }
        } else {
            cell2.useSeparator = i != getItemCount() - 1;
            if (getItemCount() == 1) {
                swipeLayout.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
            } else if (i == 0) {
                swipeLayout.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f, Theme.getColor(Theme.key_windowBackgroundWhite)));
            } else if (i == getItemCount() - 1) {
                swipeLayout.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
            }
        }
        cell2.fullSeparator = (!dialog.pinned || nextDialog == null || nextDialog.pinned) ? false : true;
        if (this.dialogsType == 0 && AndroidUtilities.isTablet()) {
            cell2.setDialogSelected(dialog.id == this.openedDialogId);
        }
        cell2.setChecked(this.selectedDialogs.contains(Long.valueOf(dialog.id)), false);
        cell2.setDialog(dialog, this.dialogsType, this.folderId);
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public int getItemViewType(int i) {
        if (this.onlineContacts != null) {
            if (i == 0) {
                return 5;
            }
            if (i == 1) {
                return 8;
            }
            if (i == 2) {
                return 7;
            }
            return 6;
        }
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
        } else if (this.showArchiveHint) {
            if (i == 0) {
                return 9;
            }
            if (i == 1) {
                return 8;
            }
            i -= 2;
        }
        int size = DialogsActivity.getDialogsArray(this.currentAccount, this.dialogsType, this.folderId, this.dialogsListFrozen).size();
        if (i == size) {
            if (MessagesController.getInstance(this.currentAccount).isDialogsEndReached(this.folderId)) {
                return size == 0 ? 5 : 10;
            }
            return 1;
        }
        if (i > size) {
            return 10;
        }
        return 0;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public void notifyItemMoved(int fromPosition, int toPosition) {
        ArrayList<TLRPC.Dialog> dialogs = DialogsActivity.getDialogsArray(this.currentAccount, this.dialogsType, this.folderId, false);
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
