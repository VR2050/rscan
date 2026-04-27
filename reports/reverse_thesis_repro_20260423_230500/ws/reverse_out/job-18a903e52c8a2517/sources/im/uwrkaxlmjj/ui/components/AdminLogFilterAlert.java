package im.uwrkaxlmjj.ui.components;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.util.SparseArray;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.ContentPreviewViewer;
import im.uwrkaxlmjj.ui.actionbar.BottomSheet;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.cells.CheckBoxCell;
import im.uwrkaxlmjj.ui.cells.CheckBoxUserCell;
import im.uwrkaxlmjj.ui.cells.ShadowSectionCell;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import java.util.ArrayList;
import java.util.regex.Pattern;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class AdminLogFilterAlert extends BottomSheet {
    private ListAdapter adapter;
    private int adminsRow;
    private int allAdminsRow;
    private ArrayList<TLRPC.ChannelParticipant> currentAdmins;
    private TLRPC.TL_channelAdminLogEventsFilter currentFilter;
    private AdminLogFilterAlertDelegate delegate;
    private int deleteRow;
    private int editRow;
    private boolean ignoreLayout;
    private int infoRow;
    private boolean isMegagroup;
    private int leavingRow;
    private RecyclerListView listView;
    private int membersRow;
    private FrameLayout pickerBottomLayout;
    private int pinnedRow;
    private int reqId;
    private int restrictionsRow;
    private BottomSheet.BottomSheetCell saveButton;
    private int scrollOffsetY;
    private SparseArray<TLRPC.User> selectedAdmins;
    private Drawable shadowDrawable;
    private Pattern urlPattern;

    public interface AdminLogFilterAlertDelegate {
        void didSelectRights(TLRPC.TL_channelAdminLogEventsFilter tL_channelAdminLogEventsFilter, SparseArray<TLRPC.User> sparseArray);
    }

    public AdminLogFilterAlert(Context context, TLRPC.TL_channelAdminLogEventsFilter filter, SparseArray<TLRPC.User> admins, boolean megagroup) {
        super(context, false, 0);
        if (filter != null) {
            TLRPC.TL_channelAdminLogEventsFilter tL_channelAdminLogEventsFilter = new TLRPC.TL_channelAdminLogEventsFilter();
            this.currentFilter = tL_channelAdminLogEventsFilter;
            tL_channelAdminLogEventsFilter.join = filter.join;
            this.currentFilter.leave = filter.leave;
            this.currentFilter.invite = filter.invite;
            this.currentFilter.ban = filter.ban;
            this.currentFilter.unban = filter.unban;
            this.currentFilter.kick = filter.kick;
            this.currentFilter.unkick = filter.unkick;
            this.currentFilter.promote = filter.promote;
            this.currentFilter.demote = filter.demote;
            this.currentFilter.info = filter.info;
            this.currentFilter.settings = filter.settings;
            this.currentFilter.pinned = filter.pinned;
            this.currentFilter.edit = filter.edit;
            this.currentFilter.delete = filter.delete;
        }
        if (admins != null) {
            this.selectedAdmins = admins.clone();
        }
        this.isMegagroup = megagroup;
        int rowCount = 1;
        if (megagroup) {
            int rowCount2 = 1 + 1;
            this.restrictionsRow = 1;
            rowCount = rowCount2;
        } else {
            this.restrictionsRow = -1;
        }
        int rowCount3 = rowCount + 1;
        this.adminsRow = rowCount;
        int rowCount4 = rowCount3 + 1;
        this.membersRow = rowCount3;
        int rowCount5 = rowCount4 + 1;
        this.infoRow = rowCount4;
        int rowCount6 = rowCount5 + 1;
        this.deleteRow = rowCount5;
        int rowCount7 = rowCount6 + 1;
        this.editRow = rowCount6;
        if (this.isMegagroup) {
            this.pinnedRow = rowCount7;
            rowCount7++;
        } else {
            this.pinnedRow = -1;
        }
        this.leavingRow = rowCount7;
        this.allAdminsRow = rowCount7 + 2;
        Drawable drawableMutate = context.getResources().getDrawable(R.drawable.sheet_shadow_round).mutate();
        this.shadowDrawable = drawableMutate;
        drawableMutate.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_dialogBackground), PorterDuff.Mode.MULTIPLY));
        this.containerView = new FrameLayout(context) { // from class: im.uwrkaxlmjj.ui.components.AdminLogFilterAlert.1
            @Override // android.view.ViewGroup
            public boolean onInterceptTouchEvent(MotionEvent ev) {
                if (ev.getAction() == 0 && AdminLogFilterAlert.this.scrollOffsetY != 0 && ev.getY() < AdminLogFilterAlert.this.scrollOffsetY) {
                    AdminLogFilterAlert.this.dismiss();
                    return true;
                }
                return super.onInterceptTouchEvent(ev);
            }

            @Override // android.view.View
            public boolean onTouchEvent(MotionEvent e) {
                return !AdminLogFilterAlert.this.isDismissed() && super.onTouchEvent(e);
            }

            @Override // android.widget.FrameLayout, android.view.View
            protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                int height = View.MeasureSpec.getSize(heightMeasureSpec);
                if (Build.VERSION.SDK_INT >= 21) {
                    height -= AndroidUtilities.statusBarHeight;
                }
                getMeasuredWidth();
                int contentSize = AndroidUtilities.dp(48.0f) + ((AdminLogFilterAlert.this.isMegagroup ? 9 : 7) * AndroidUtilities.dp(48.0f)) + AdminLogFilterAlert.this.backgroundPaddingTop;
                if (AdminLogFilterAlert.this.currentAdmins != null) {
                    contentSize += ((AdminLogFilterAlert.this.currentAdmins.size() + 1) * AndroidUtilities.dp(48.0f)) + AndroidUtilities.dp(20.0f);
                }
                int padding = ((float) contentSize) < ((float) (height / 5)) * 3.2f ? 0 : (height / 5) * 2;
                if (padding != 0 && contentSize < height) {
                    padding -= height - contentSize;
                }
                if (padding == 0) {
                    padding = AdminLogFilterAlert.this.backgroundPaddingTop;
                }
                if (AdminLogFilterAlert.this.listView.getPaddingTop() != padding) {
                    AdminLogFilterAlert.this.ignoreLayout = true;
                    AdminLogFilterAlert.this.listView.setPadding(0, padding, 0, 0);
                    AdminLogFilterAlert.this.ignoreLayout = false;
                }
                super.onMeasure(widthMeasureSpec, View.MeasureSpec.makeMeasureSpec(Math.min(contentSize, height), 1073741824));
            }

            @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
            protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
                super.onLayout(changed, left, top, right, bottom);
                AdminLogFilterAlert.this.updateLayout();
            }

            @Override // android.view.View, android.view.ViewParent
            public void requestLayout() {
                if (AdminLogFilterAlert.this.ignoreLayout) {
                    return;
                }
                super.requestLayout();
            }

            @Override // android.view.View
            protected void onDraw(Canvas canvas) {
                AdminLogFilterAlert.this.shadowDrawable.setBounds(0, AdminLogFilterAlert.this.scrollOffsetY - AdminLogFilterAlert.this.backgroundPaddingTop, getMeasuredWidth(), getMeasuredHeight());
                AdminLogFilterAlert.this.shadowDrawable.draw(canvas);
            }
        };
        this.containerView.setWillNotDraw(false);
        this.containerView.setPadding(this.backgroundPaddingLeft, 0, this.backgroundPaddingLeft, 0);
        RecyclerListView recyclerListView = new RecyclerListView(context) { // from class: im.uwrkaxlmjj.ui.components.AdminLogFilterAlert.2
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup
            public boolean onInterceptTouchEvent(MotionEvent event) {
                boolean result = ContentPreviewViewer.getInstance().onInterceptTouchEvent(event, AdminLogFilterAlert.this.listView, 0, null);
                return super.onInterceptTouchEvent(event) || result;
            }

            @Override // androidx.recyclerview.widget.RecyclerView, android.view.View, android.view.ViewParent
            public void requestLayout() {
                if (AdminLogFilterAlert.this.ignoreLayout) {
                    return;
                }
                super.requestLayout();
            }
        };
        this.listView = recyclerListView;
        recyclerListView.setLayoutManager(new LinearLayoutManager(getContext(), 1, false));
        RecyclerListView recyclerListView2 = this.listView;
        ListAdapter listAdapter = new ListAdapter(context);
        this.adapter = listAdapter;
        recyclerListView2.setAdapter(listAdapter);
        this.listView.setVerticalScrollBarEnabled(false);
        this.listView.setClipToPadding(false);
        this.listView.setEnabled(true);
        this.listView.setGlowColor(Theme.getColor(Theme.key_dialogScrollGlow));
        this.listView.setOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.components.AdminLogFilterAlert.3
            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
                AdminLogFilterAlert.this.updateLayout();
            }
        });
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AdminLogFilterAlert$fVDAJIzcIXKIOHW-_UBB38mRDKk
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$new$0$AdminLogFilterAlert(view, i);
            }
        });
        this.containerView.addView(this.listView, LayoutHelper.createFrame(-1.0f, -1.0f, 51, 0.0f, 0.0f, 0.0f, 48.0f));
        View shadow = new View(context);
        shadow.setBackgroundResource(R.drawable.header_shadow_reverse);
        this.containerView.addView(shadow, LayoutHelper.createFrame(-1.0f, 3.0f, 83, 0.0f, 0.0f, 0.0f, 48.0f));
        BottomSheet.BottomSheetCell bottomSheetCell = new BottomSheet.BottomSheetCell(context, 1);
        this.saveButton = bottomSheetCell;
        bottomSheetCell.setBackgroundDrawable(Theme.getSelectorDrawable(false));
        this.saveButton.setTextAndIcon(LocaleController.getString("Save", R.string.Save).toUpperCase(), 0);
        this.saveButton.setTextColor(Theme.getColor(Theme.key_dialogTextBlue2));
        this.saveButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$AdminLogFilterAlert$LUOVe5AEc0QfVj5Oe_bH3Xu-3KQ
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$new$1$AdminLogFilterAlert(view);
            }
        });
        this.containerView.addView(this.saveButton, LayoutHelper.createFrame(-1, 48, 83));
        this.adapter.notifyDataSetChanged();
    }

    public /* synthetic */ void lambda$new$0$AdminLogFilterAlert(View view, int position) {
        if (view instanceof CheckBoxCell) {
            CheckBoxCell cell = (CheckBoxCell) view;
            boolean isChecked = cell.isChecked();
            cell.setChecked(!isChecked, true);
            if (position == 0) {
                if (isChecked) {
                    TLRPC.TL_channelAdminLogEventsFilter tL_channelAdminLogEventsFilter = new TLRPC.TL_channelAdminLogEventsFilter();
                    this.currentFilter = tL_channelAdminLogEventsFilter;
                    tL_channelAdminLogEventsFilter.delete = false;
                    tL_channelAdminLogEventsFilter.edit = false;
                    tL_channelAdminLogEventsFilter.pinned = false;
                    tL_channelAdminLogEventsFilter.settings = false;
                    tL_channelAdminLogEventsFilter.info = false;
                    tL_channelAdminLogEventsFilter.demote = false;
                    tL_channelAdminLogEventsFilter.promote = false;
                    tL_channelAdminLogEventsFilter.unkick = false;
                    tL_channelAdminLogEventsFilter.kick = false;
                    tL_channelAdminLogEventsFilter.unban = false;
                    tL_channelAdminLogEventsFilter.ban = false;
                    tL_channelAdminLogEventsFilter.invite = false;
                    tL_channelAdminLogEventsFilter.leave = false;
                    tL_channelAdminLogEventsFilter.join = false;
                } else {
                    this.currentFilter = null;
                }
                int count = this.listView.getChildCount();
                for (int a = 0; a < count; a++) {
                    View child = this.listView.getChildAt(a);
                    RecyclerView.ViewHolder holder = this.listView.findContainingViewHolder(child);
                    int pos = holder.getAdapterPosition();
                    if (holder.getItemViewType() == 0 && pos > 0 && pos < this.allAdminsRow - 1) {
                        ((CheckBoxCell) child).setChecked(!isChecked, true);
                    }
                }
            } else if (position == this.allAdminsRow) {
                if (isChecked) {
                    this.selectedAdmins = new SparseArray<>();
                } else {
                    this.selectedAdmins = null;
                }
                int count2 = this.listView.getChildCount();
                for (int a2 = 0; a2 < count2; a2++) {
                    View child2 = this.listView.getChildAt(a2);
                    RecyclerView.ViewHolder holder2 = this.listView.findContainingViewHolder(child2);
                    holder2.getAdapterPosition();
                    if (holder2.getItemViewType() == 2) {
                        CheckBoxUserCell userCell = (CheckBoxUserCell) child2;
                        userCell.setChecked(!isChecked, true);
                    }
                }
            } else {
                if (this.currentFilter == null) {
                    TLRPC.TL_channelAdminLogEventsFilter tL_channelAdminLogEventsFilter2 = new TLRPC.TL_channelAdminLogEventsFilter();
                    this.currentFilter = tL_channelAdminLogEventsFilter2;
                    tL_channelAdminLogEventsFilter2.delete = true;
                    tL_channelAdminLogEventsFilter2.edit = true;
                    tL_channelAdminLogEventsFilter2.pinned = true;
                    tL_channelAdminLogEventsFilter2.settings = true;
                    tL_channelAdminLogEventsFilter2.info = true;
                    tL_channelAdminLogEventsFilter2.demote = true;
                    tL_channelAdminLogEventsFilter2.promote = true;
                    tL_channelAdminLogEventsFilter2.unkick = true;
                    tL_channelAdminLogEventsFilter2.kick = true;
                    tL_channelAdminLogEventsFilter2.unban = true;
                    tL_channelAdminLogEventsFilter2.ban = true;
                    tL_channelAdminLogEventsFilter2.invite = true;
                    tL_channelAdminLogEventsFilter2.leave = true;
                    tL_channelAdminLogEventsFilter2.join = true;
                    RecyclerView.ViewHolder holder3 = this.listView.findViewHolderForAdapterPosition(0);
                    if (holder3 != null) {
                        ((CheckBoxCell) holder3.itemView).setChecked(false, true);
                    }
                }
                if (position == this.restrictionsRow) {
                    TLRPC.TL_channelAdminLogEventsFilter tL_channelAdminLogEventsFilter3 = this.currentFilter;
                    boolean z = !tL_channelAdminLogEventsFilter3.kick;
                    tL_channelAdminLogEventsFilter3.unban = z;
                    tL_channelAdminLogEventsFilter3.unkick = z;
                    tL_channelAdminLogEventsFilter3.ban = z;
                    tL_channelAdminLogEventsFilter3.kick = z;
                } else if (position == this.adminsRow) {
                    TLRPC.TL_channelAdminLogEventsFilter tL_channelAdminLogEventsFilter4 = this.currentFilter;
                    boolean z2 = !tL_channelAdminLogEventsFilter4.demote;
                    tL_channelAdminLogEventsFilter4.demote = z2;
                    tL_channelAdminLogEventsFilter4.promote = z2;
                } else if (position == this.membersRow) {
                    TLRPC.TL_channelAdminLogEventsFilter tL_channelAdminLogEventsFilter5 = this.currentFilter;
                    boolean z3 = !tL_channelAdminLogEventsFilter5.join;
                    tL_channelAdminLogEventsFilter5.join = z3;
                    tL_channelAdminLogEventsFilter5.invite = z3;
                } else if (position == this.infoRow) {
                    TLRPC.TL_channelAdminLogEventsFilter tL_channelAdminLogEventsFilter6 = this.currentFilter;
                    boolean z4 = !tL_channelAdminLogEventsFilter6.info;
                    tL_channelAdminLogEventsFilter6.settings = z4;
                    tL_channelAdminLogEventsFilter6.info = z4;
                } else if (position == this.deleteRow) {
                    this.currentFilter.delete = !r4.delete;
                } else if (position == this.editRow) {
                    this.currentFilter.edit = !r4.edit;
                } else if (position == this.pinnedRow) {
                    this.currentFilter.pinned = !r4.pinned;
                } else if (position == this.leavingRow) {
                    this.currentFilter.leave = !r4.leave;
                }
            }
            TLRPC.TL_channelAdminLogEventsFilter tL_channelAdminLogEventsFilter7 = this.currentFilter;
            if (tL_channelAdminLogEventsFilter7 != null && !tL_channelAdminLogEventsFilter7.join && !this.currentFilter.leave && !this.currentFilter.leave && !this.currentFilter.invite && !this.currentFilter.ban && !this.currentFilter.unban && !this.currentFilter.kick && !this.currentFilter.unkick && !this.currentFilter.promote && !this.currentFilter.demote && !this.currentFilter.info && !this.currentFilter.settings && !this.currentFilter.pinned && !this.currentFilter.edit && !this.currentFilter.delete) {
                this.saveButton.setEnabled(false);
                this.saveButton.setAlpha(0.5f);
            } else {
                this.saveButton.setEnabled(true);
                this.saveButton.setAlpha(1.0f);
            }
            updateCheckBoxStatus(false);
            return;
        }
        if (view instanceof CheckBoxUserCell) {
            CheckBoxUserCell checkBoxUserCell = (CheckBoxUserCell) view;
            if (this.selectedAdmins == null) {
                this.selectedAdmins = new SparseArray<>();
                RecyclerView.ViewHolder holder4 = this.listView.findViewHolderForAdapterPosition(this.allAdminsRow);
                if (holder4 != null) {
                    ((CheckBoxCell) holder4.itemView).setChecked(false, true);
                }
                for (int a3 = 0; a3 < this.currentAdmins.size(); a3++) {
                    TLRPC.User user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(this.currentAdmins.get(a3).user_id));
                    this.selectedAdmins.put(user.id, user);
                }
            }
            boolean isChecked2 = checkBoxUserCell.isChecked();
            TLRPC.User user2 = checkBoxUserCell.getCurrentUser();
            if (isChecked2) {
                this.selectedAdmins.remove(user2.id);
            } else {
                this.selectedAdmins.put(user2.id, user2);
            }
            checkBoxUserCell.setChecked(!isChecked2, true);
            updateCheckBoxStatus(true);
        }
    }

    public /* synthetic */ void lambda$new$1$AdminLogFilterAlert(View v) {
        this.delegate.didSelectRights(this.currentFilter, this.selectedAdmins);
        dismiss();
    }

    public void setCurrentAdmins(ArrayList<TLRPC.ChannelParticipant> admins) {
        this.currentAdmins = admins;
        ListAdapter listAdapter = this.adapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
    }

    private void updateCheckBoxStatus(boolean isCheckBoxUserCell) {
        RecyclerListView recyclerListView;
        if (this.currentFilter == null || (recyclerListView = this.listView) == null) {
            return;
        }
        View child = isCheckBoxUserCell ? recyclerListView.getChildAt(this.allAdminsRow) : recyclerListView.getChildAt(0);
        if (child instanceof CheckBoxCell) {
            if (isCheckBoxUserCell) {
                SparseArray<TLRPC.User> sparseArray = this.selectedAdmins;
                if (sparseArray == null || this.currentAdmins == null || sparseArray.size() != this.currentAdmins.size()) {
                    ((CheckBoxUserCell) child).setChecked(false, true);
                    return;
                } else {
                    ((CheckBoxUserCell) child).setChecked(true, true);
                    return;
                }
            }
            if (this.isMegagroup) {
                if (!this.currentFilter.join || !this.currentFilter.leave || !this.currentFilter.leave || !this.currentFilter.invite || !this.currentFilter.ban || !this.currentFilter.unban || !this.currentFilter.kick || !this.currentFilter.unkick || !this.currentFilter.promote || !this.currentFilter.demote || !this.currentFilter.info || !this.currentFilter.settings || !this.currentFilter.pinned || !this.currentFilter.edit || !this.currentFilter.delete) {
                    ((CheckBoxCell) child).setChecked(false, true);
                    return;
                } else {
                    ((CheckBoxCell) child).setChecked(true, true);
                    return;
                }
            }
            if (!this.currentFilter.join || !this.currentFilter.leave || !this.currentFilter.leave || !this.currentFilter.invite || !this.currentFilter.promote || !this.currentFilter.demote || !this.currentFilter.info || !this.currentFilter.settings || !this.currentFilter.edit || !this.currentFilter.delete) {
                ((CheckBoxCell) child).setChecked(false, true);
            } else {
                ((CheckBoxCell) child).setChecked(true, true);
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BottomSheet
    protected boolean canDismissWithSwipe() {
        return false;
    }

    public void setAdminLogFilterAlertDelegate(AdminLogFilterAlertDelegate adminLogFilterAlertDelegate) {
        this.delegate = adminLogFilterAlertDelegate;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateLayout() {
        if (this.listView.getChildCount() <= 0) {
            RecyclerListView recyclerListView = this.listView;
            int paddingTop = recyclerListView.getPaddingTop();
            this.scrollOffsetY = paddingTop;
            recyclerListView.setTopGlowOffset(paddingTop);
            this.containerView.invalidate();
            return;
        }
        int newOffset = 0;
        View child = this.listView.getChildAt(0);
        RecyclerListView.Holder holder = (RecyclerListView.Holder) this.listView.findContainingViewHolder(child);
        int top = child.getTop() - AndroidUtilities.dp(8.0f);
        if (top > 0 && holder != null && holder.getAdapterPosition() == 0) {
            newOffset = top;
        }
        if (this.scrollOffsetY != newOffset) {
            RecyclerListView recyclerListView2 = this.listView;
            this.scrollOffsetY = newOffset;
            recyclerListView2.setTopGlowOffset(newOffset);
            this.containerView.invalidate();
        }
    }

    private class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context context;

        public ListAdapter(Context context) {
            this.context = context;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return (AdminLogFilterAlert.this.isMegagroup ? 9 : 7) + (AdminLogFilterAlert.this.currentAdmins != null ? AdminLogFilterAlert.this.currentAdmins.size() + 2 : 0);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position < AdminLogFilterAlert.this.allAdminsRow - 1 || position == AdminLogFilterAlert.this.allAdminsRow) {
                return 0;
            }
            return position == AdminLogFilterAlert.this.allAdminsRow - 1 ? 1 : 2;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return holder.getItemViewType() != 1;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            FrameLayout view = null;
            if (viewType != 0) {
                if (viewType == 1) {
                    ShadowSectionCell shadowSectionCell = new ShadowSectionCell(this.context, 18);
                    view = new FrameLayout(this.context);
                    view.addView(shadowSectionCell, LayoutHelper.createFrame(-1, -1.0f));
                    view.setBackgroundColor(Theme.getColor(Theme.key_dialogBackgroundGray));
                } else if (viewType == 2) {
                    view = new CheckBoxUserCell(this.context, true);
                }
            } else {
                view = new CheckBoxCell(this.context, 1, 21);
                view.setBackgroundDrawable(Theme.getSelectorDrawable(false));
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onViewAttachedToWindow(RecyclerView.ViewHolder holder) {
            int position = holder.getAdapterPosition();
            int itemViewType = holder.getItemViewType();
            if (itemViewType != 0) {
                if (itemViewType == 2) {
                    CheckBoxUserCell userCell = (CheckBoxUserCell) holder.itemView;
                    int userId = ((TLRPC.ChannelParticipant) AdminLogFilterAlert.this.currentAdmins.get((position - AdminLogFilterAlert.this.allAdminsRow) - 1)).user_id;
                    if (AdminLogFilterAlert.this.selectedAdmins != null && AdminLogFilterAlert.this.selectedAdmins.indexOfKey(userId) < 0) {
                        z = false;
                    }
                    userCell.setChecked(z, false);
                    return;
                }
                return;
            }
            CheckBoxCell cell = (CheckBoxCell) holder.itemView;
            if (position == 0) {
                cell.setChecked(AdminLogFilterAlert.this.currentFilter == null, false);
                return;
            }
            if (position == AdminLogFilterAlert.this.restrictionsRow) {
                if (AdminLogFilterAlert.this.currentFilter != null && (!AdminLogFilterAlert.this.currentFilter.kick || !AdminLogFilterAlert.this.currentFilter.ban || !AdminLogFilterAlert.this.currentFilter.unkick || !AdminLogFilterAlert.this.currentFilter.unban)) {
                    z = false;
                }
                cell.setChecked(z, false);
                return;
            }
            if (position == AdminLogFilterAlert.this.adminsRow) {
                if (AdminLogFilterAlert.this.currentFilter != null && (!AdminLogFilterAlert.this.currentFilter.promote || !AdminLogFilterAlert.this.currentFilter.demote)) {
                    z = false;
                }
                cell.setChecked(z, false);
                return;
            }
            if (position == AdminLogFilterAlert.this.membersRow) {
                if (AdminLogFilterAlert.this.currentFilter != null && (!AdminLogFilterAlert.this.currentFilter.invite || !AdminLogFilterAlert.this.currentFilter.join)) {
                    z = false;
                }
                cell.setChecked(z, false);
                return;
            }
            if (position == AdminLogFilterAlert.this.infoRow) {
                if (AdminLogFilterAlert.this.currentFilter != null && !AdminLogFilterAlert.this.currentFilter.info) {
                    z = false;
                }
                cell.setChecked(z, false);
                return;
            }
            if (position == AdminLogFilterAlert.this.deleteRow) {
                if (AdminLogFilterAlert.this.currentFilter != null && !AdminLogFilterAlert.this.currentFilter.delete) {
                    z = false;
                }
                cell.setChecked(z, false);
                return;
            }
            if (position == AdminLogFilterAlert.this.editRow) {
                if (AdminLogFilterAlert.this.currentFilter != null && !AdminLogFilterAlert.this.currentFilter.edit) {
                    z = false;
                }
                cell.setChecked(z, false);
                return;
            }
            if (position == AdminLogFilterAlert.this.pinnedRow) {
                if (AdminLogFilterAlert.this.currentFilter != null && !AdminLogFilterAlert.this.currentFilter.pinned) {
                    z = false;
                }
                cell.setChecked(z, false);
                return;
            }
            if (position == AdminLogFilterAlert.this.leavingRow) {
                if (AdminLogFilterAlert.this.currentFilter != null && !AdminLogFilterAlert.this.currentFilter.leave) {
                    z = false;
                }
                cell.setChecked(z, false);
                return;
            }
            if (position == AdminLogFilterAlert.this.allAdminsRow) {
                cell.setChecked(AdminLogFilterAlert.this.selectedAdmins == null, false);
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            int itemViewType = holder.getItemViewType();
            boolean z = true;
            if (itemViewType != 0) {
                if (itemViewType == 2) {
                    CheckBoxUserCell userCell = (CheckBoxUserCell) holder.itemView;
                    int userId = ((TLRPC.ChannelParticipant) AdminLogFilterAlert.this.currentAdmins.get((position - AdminLogFilterAlert.this.allAdminsRow) - 1)).user_id;
                    userCell.setUser(MessagesController.getInstance(AdminLogFilterAlert.this.currentAccount).getUser(Integer.valueOf(userId)), AdminLogFilterAlert.this.selectedAdmins == null || AdminLogFilterAlert.this.selectedAdmins.indexOfKey(userId) >= 0, position != getItemCount() - 1);
                    return;
                }
                return;
            }
            CheckBoxCell cell = (CheckBoxCell) holder.itemView;
            if (position != 0) {
                if (position != AdminLogFilterAlert.this.restrictionsRow) {
                    if (position != AdminLogFilterAlert.this.adminsRow) {
                        if (position != AdminLogFilterAlert.this.membersRow) {
                            if (position == AdminLogFilterAlert.this.infoRow) {
                                if (AdminLogFilterAlert.this.isMegagroup) {
                                    cell.setText(LocaleController.getString("EventLogFilterGroupInfo", R.string.EventLogFilterGroupInfo), "", AdminLogFilterAlert.this.currentFilter == null || AdminLogFilterAlert.this.currentFilter.info, true);
                                    return;
                                } else {
                                    cell.setText(LocaleController.getString("EventLogFilterChannelInfo", R.string.EventLogFilterChannelInfo), "", AdminLogFilterAlert.this.currentFilter == null || AdminLogFilterAlert.this.currentFilter.info, true);
                                    return;
                                }
                            }
                            if (position != AdminLogFilterAlert.this.deleteRow) {
                                if (position != AdminLogFilterAlert.this.editRow) {
                                    if (position != AdminLogFilterAlert.this.pinnedRow) {
                                        if (position != AdminLogFilterAlert.this.leavingRow) {
                                            if (position == AdminLogFilterAlert.this.allAdminsRow) {
                                                cell.setText(LocaleController.getString("EventLogAllAdmins", R.string.EventLogAllAdmins), "", AdminLogFilterAlert.this.selectedAdmins == null, true);
                                                return;
                                            }
                                            return;
                                        } else {
                                            String string = LocaleController.getString("EventLogFilterLeavingMembers", R.string.EventLogFilterLeavingMembers);
                                            if (AdminLogFilterAlert.this.currentFilter != null && !AdminLogFilterAlert.this.currentFilter.leave) {
                                                z = false;
                                            }
                                            cell.setText(string, "", z, false);
                                            return;
                                        }
                                    }
                                    cell.setText(LocaleController.getString("EventLogFilterPinnedMessages", R.string.EventLogFilterPinnedMessages), "", AdminLogFilterAlert.this.currentFilter == null || AdminLogFilterAlert.this.currentFilter.pinned, true);
                                    return;
                                }
                                cell.setText(LocaleController.getString("EventLogFilterEditedMessages", R.string.EventLogFilterEditedMessages), "", AdminLogFilterAlert.this.currentFilter == null || AdminLogFilterAlert.this.currentFilter.edit, true);
                                return;
                            }
                            cell.setText(LocaleController.getString("EventLogFilterDeletedMessages", R.string.EventLogFilterDeletedMessages), "", AdminLogFilterAlert.this.currentFilter == null || AdminLogFilterAlert.this.currentFilter.delete, true);
                            return;
                        }
                        String string2 = LocaleController.getString("EventLogFilterNewMembers", R.string.EventLogFilterNewMembers);
                        if (AdminLogFilterAlert.this.currentFilter == null || (AdminLogFilterAlert.this.currentFilter.invite && AdminLogFilterAlert.this.currentFilter.join)) {
                            z = true;
                        }
                        cell.setText(string2, "", z, true);
                        return;
                    }
                    String string3 = LocaleController.getString("EventLogFilterNewAdmins", R.string.EventLogFilterNewAdmins);
                    if (AdminLogFilterAlert.this.currentFilter == null || (AdminLogFilterAlert.this.currentFilter.promote && AdminLogFilterAlert.this.currentFilter.demote)) {
                        z = true;
                    }
                    cell.setText(string3, "", z, true);
                    return;
                }
                String string4 = LocaleController.getString("EventLogFilterNewRestrictions", R.string.EventLogFilterNewRestrictions);
                if (AdminLogFilterAlert.this.currentFilter == null || (AdminLogFilterAlert.this.currentFilter.kick && AdminLogFilterAlert.this.currentFilter.ban && AdminLogFilterAlert.this.currentFilter.unkick && AdminLogFilterAlert.this.currentFilter.unban)) {
                    z = true;
                }
                cell.setText(string4, "", z, true);
                return;
            }
            cell.setText(LocaleController.getString("EventLogFilterAll", R.string.EventLogFilterAll), "", AdminLogFilterAlert.this.currentFilter == null, true);
        }
    }
}
