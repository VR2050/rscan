package im.uwrkaxlmjj.ui;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.content.Context;
import android.content.DialogInterface;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.util.Property;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.DefaultItemAnimator;
import androidx.recyclerview.widget.ItemTouchHelper;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.PollCreateActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.SimpleTextView;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.cells.HeaderCell;
import im.uwrkaxlmjj.ui.cells.PollEditTextCell;
import im.uwrkaxlmjj.ui.cells.ShadowSectionCell;
import im.uwrkaxlmjj.ui.cells.TextInfoPrivacyCell;
import im.uwrkaxlmjj.ui.cells.TextSettingsCell;
import im.uwrkaxlmjj.ui.components.AlertsCreator;
import im.uwrkaxlmjj.ui.components.ContextProgressView;
import im.uwrkaxlmjj.ui.components.EditTextBoldCursor;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class PollCreateActivity extends BaseFragment {
    private static final int MAX_ANSWER_LENGTH = 100;
    private static final int MAX_QUESTION_LENGTH = 255;
    private static final int done_button = 1;
    private int addAnswerRow;
    private int answerHeaderRow;
    private int answerSectionRow;
    private int answerStartRow;
    private PollCreateActivityDelegate delegate;
    private ActionBarMenuItem doneItem;
    private AnimatorSet doneItemAnimation;
    private ListAdapter listAdapter;
    private RecyclerListView listView;
    private ChatActivity parentFragment;
    private ContextProgressView progressView;
    private int questionHeaderRow;
    private int questionRow;
    private int questionSectionRow;
    private String questionString;
    private int rowCount;
    private String[] answers = new String[10];
    private int answersCount = 1;
    private int requestFieldFocusAtPosition = -1;

    public interface PollCreateActivityDelegate {
        void sendPoll(TLRPC.TL_messageMediaPoll tL_messageMediaPoll, boolean z, int i);
    }

    static /* synthetic */ int access$1410(PollCreateActivity x0) {
        int i = x0.answersCount;
        x0.answersCount = i - 1;
        return i;
    }

    public class TouchHelperCallback extends ItemTouchHelper.Callback {
        public TouchHelperCallback() {
        }

        @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
        public boolean isLongPressDragEnabled() {
            return true;
        }

        @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
        public int getMovementFlags(RecyclerView recyclerView, RecyclerView.ViewHolder viewHolder) {
            if (viewHolder.getItemViewType() != 5) {
                return makeMovementFlags(0, 0);
            }
            return makeMovementFlags(3, 0);
        }

        @Override // androidx.recyclerview.widget.ItemTouchHelper.Callback
        public boolean onMove(RecyclerView recyclerView, RecyclerView.ViewHolder source, RecyclerView.ViewHolder target) {
            if (source.getItemViewType() == target.getItemViewType()) {
                PollCreateActivity.this.listAdapter.swapElements(source.getAdapterPosition(), target.getAdapterPosition());
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
                PollCreateActivity.this.listView.cancelClickRunnables(false);
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

    public PollCreateActivity(ChatActivity chatActivity) {
        this.parentFragment = chatActivity;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        updateRows();
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setTitle(LocaleController.getString("NewPoll", R.string.NewPoll));
        if (AndroidUtilities.isTablet()) {
            this.actionBar.setOccupyStatusBar(false);
        }
        this.actionBar.setAllowOverlayTitle(true);
        this.actionBar.setActionBarMenuOnItemClick(new AnonymousClass1());
        ActionBarMenu menu = this.actionBar.createMenu();
        this.doneItem = menu.addItemWithWidth(1, R.drawable.ic_done, AndroidUtilities.dp(56.0f), LocaleController.getString("Done", R.string.Done));
        ContextProgressView contextProgressView = new ContextProgressView(context, 1);
        this.progressView = contextProgressView;
        contextProgressView.setAlpha(0.0f);
        this.progressView.setScaleX(0.1f);
        this.progressView.setScaleY(0.1f);
        this.progressView.setVisibility(4);
        this.doneItem.addView(this.progressView, LayoutHelper.createFrame(-1, -1.0f));
        this.listAdapter = new ListAdapter(context);
        this.fragmentView = new FrameLayout(context);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        FrameLayout frameLayout = (FrameLayout) this.fragmentView;
        RecyclerListView recyclerListView = new RecyclerListView(context) { // from class: im.uwrkaxlmjj.ui.PollCreateActivity.2
            @Override // androidx.recyclerview.widget.RecyclerView, android.view.ViewGroup, android.view.ViewParent
            public boolean requestChildRectangleOnScreen(View child, Rect rectangle, boolean immediate) {
                rectangle.bottom += AndroidUtilities.dp(60.0f);
                return super.requestChildRectangleOnScreen(child, rectangle, immediate);
            }

            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView, androidx.recyclerview.widget.RecyclerView, android.view.View
            protected void onMeasure(int widthSpec, int heightSpec) {
                super.onMeasure(widthSpec, heightSpec);
            }

            @Override // androidx.recyclerview.widget.RecyclerView, android.view.View, android.view.ViewParent
            public void requestLayout() {
                super.requestLayout();
            }
        };
        this.listView = recyclerListView;
        recyclerListView.setVerticalScrollBarEnabled(false);
        ((DefaultItemAnimator) this.listView.getItemAnimator()).setDelayAnimations(false);
        this.listView.setLayoutManager(new LinearLayoutManager(context, 1, false));
        ItemTouchHelper itemTouchHelper = new ItemTouchHelper(new TouchHelperCallback());
        itemTouchHelper.attachToRecyclerView(this.listView);
        frameLayout.addView(this.listView, LayoutHelper.createFrame(-1, -1, 51));
        this.listView.setAdapter(this.listAdapter);
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PollCreateActivity$BSfhqNPjaEPLwliYnIn9_viSudc
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$createView$0$PollCreateActivity(view, i);
            }
        });
        checkDoneButton();
        return this.fragmentView;
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.PollCreateActivity$1, reason: invalid class name */
    class AnonymousClass1 extends ActionBar.ActionBarMenuOnItemClick {
        AnonymousClass1() {
        }

        @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
        public void onItemClick(int id) {
            if (id == -1) {
                if (PollCreateActivity.this.checkDiscard()) {
                    PollCreateActivity.this.finishFragment();
                    return;
                }
                return;
            }
            if (id == 1) {
                final TLRPC.TL_messageMediaPoll poll = new TLRPC.TL_messageMediaPoll();
                poll.poll = new TLRPC.TL_poll();
                TLRPC.TL_poll tL_poll = poll.poll;
                PollCreateActivity pollCreateActivity = PollCreateActivity.this;
                tL_poll.question = pollCreateActivity.getFixedString(pollCreateActivity.questionString);
                for (int a = 0; a < PollCreateActivity.this.answers.length; a++) {
                    PollCreateActivity pollCreateActivity2 = PollCreateActivity.this;
                    if (!TextUtils.isEmpty(pollCreateActivity2.getFixedString(pollCreateActivity2.answers[a]))) {
                        TLRPC.TL_pollAnswer answer = new TLRPC.TL_pollAnswer();
                        PollCreateActivity pollCreateActivity3 = PollCreateActivity.this;
                        answer.text = pollCreateActivity3.getFixedString(pollCreateActivity3.answers[a]);
                        answer.option = new byte[1];
                        answer.option[0] = (byte) (poll.poll.answers.size() + 48);
                        poll.poll.answers.add(answer);
                    }
                }
                poll.results = new TLRPC.TL_pollResults();
                if (PollCreateActivity.this.parentFragment.isInScheduleMode()) {
                    AlertsCreator.createScheduleDatePickerDialog(PollCreateActivity.this.getParentActivity(), UserObject.isUserSelf(PollCreateActivity.this.parentFragment.getCurrentUser()), new AlertsCreator.ScheduleDatePickerDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PollCreateActivity$1$lqyT4MAUl5yByh6v4SAZuKkQPV0
                        @Override // im.uwrkaxlmjj.ui.components.AlertsCreator.ScheduleDatePickerDelegate
                        public final void didSelectDate(boolean z, int i) {
                            this.f$0.lambda$onItemClick$0$PollCreateActivity$1(poll, z, i);
                        }
                    });
                } else {
                    PollCreateActivity.this.delegate.sendPoll(poll, true, 0);
                    PollCreateActivity.this.finishFragment();
                }
            }
        }

        public /* synthetic */ void lambda$onItemClick$0$PollCreateActivity$1(TLRPC.TL_messageMediaPoll poll, boolean notify, int scheduleDate) {
            PollCreateActivity.this.delegate.sendPoll(poll, notify, scheduleDate);
            PollCreateActivity.this.finishFragment();
        }
    }

    public /* synthetic */ void lambda$createView$0$PollCreateActivity(View view, int position) {
        if (position == this.addAnswerRow) {
            addNewField();
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

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    protected void onTransitionAnimationEnd(boolean isOpen, boolean backward) {
        if (isOpen) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PollCreateActivity$DgkUCyXQHCRpa95EiWVsEx-psos
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onTransitionAnimationEnd$1$PollCreateActivity();
                }
            }, 100L);
        }
    }

    public /* synthetic */ void lambda$onTransitionAnimationEnd$1$PollCreateActivity() {
        RecyclerView.ViewHolder holder;
        RecyclerListView recyclerListView = this.listView;
        if (recyclerListView != null && (holder = recyclerListView.findViewHolderForAdapterPosition(this.questionRow)) != null) {
            PollEditTextCell textCell = (PollEditTextCell) holder.itemView;
            EditTextBoldCursor editText = textCell.getTextView();
            editText.requestFocus();
            AndroidUtilities.showKeyboard(editText);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public String getFixedString(String text) {
        if (TextUtils.isEmpty(text)) {
            return text;
        }
        String text2 = AndroidUtilities.getTrimmedString(text).toString();
        while (text2.contains("\n\n\n")) {
            text2 = text2.replace("\n\n\n", "\n\n");
        }
        while (text2.startsWith("\n\n\n")) {
            text2 = text2.replace("\n\n\n", "\n\n");
        }
        return text2;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void checkDoneButton() {
        boolean enabled = true;
        if (TextUtils.isEmpty(getFixedString(this.questionString)) || this.questionString.length() > 255) {
            enabled = false;
        } else {
            int count = 0;
            int a = 0;
            while (true) {
                String[] strArr = this.answers;
                if (a >= strArr.length) {
                    break;
                }
                if (!TextUtils.isEmpty(getFixedString(strArr[a]))) {
                    if (this.answers[a].length() > 100) {
                        count = 0;
                        break;
                    }
                    count++;
                }
                a++;
            }
            if (count < 2) {
                enabled = false;
            }
        }
        this.doneItem.setEnabled(enabled);
        this.doneItem.setAlpha(enabled ? 1.0f : 0.5f);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateRows() {
        this.rowCount = 0;
        int i = 0 + 1;
        this.rowCount = i;
        this.questionHeaderRow = 0;
        int i2 = i + 1;
        this.rowCount = i2;
        this.questionRow = i;
        int i3 = i2 + 1;
        this.rowCount = i3;
        this.questionSectionRow = i2;
        int i4 = i3 + 1;
        this.rowCount = i4;
        this.answerHeaderRow = i3;
        int i5 = this.answersCount;
        if (i5 != 0) {
            this.answerStartRow = i4;
            this.rowCount = i4 + i5;
        } else {
            this.answerStartRow = -1;
        }
        if (this.answersCount != this.answers.length) {
            int i6 = this.rowCount;
            this.rowCount = i6 + 1;
            this.addAnswerRow = i6;
        } else {
            this.addAnswerRow = -1;
        }
        int i7 = this.rowCount;
        this.rowCount = i7 + 1;
        this.answerSectionRow = i7;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onBackPressed() {
        return checkDiscard();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean checkDiscard() {
        boolean allowDiscard = TextUtils.isEmpty(getFixedString(this.questionString));
        if (allowDiscard) {
            for (int a = 0; a < this.answersCount && (allowDiscard = TextUtils.isEmpty(getFixedString(this.answers[a]))); a++) {
            }
        }
        if (!allowDiscard) {
            AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
            builder.setTitle(LocaleController.getString("CancelPollAlertTitle", R.string.CancelPollAlertTitle));
            builder.setMessage(LocaleController.getString("CancelPollAlertText", R.string.CancelPollAlertText));
            builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PollCreateActivity$WMb7Li1glvf2OTLScDcg6cO8bIw
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$checkDiscard$2$PollCreateActivity(dialogInterface, i);
                }
            });
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            showDialog(builder.create());
        }
        return allowDiscard;
    }

    public /* synthetic */ void lambda$checkDiscard$2$PollCreateActivity(DialogInterface dialogInterface, int i) {
        finishFragment();
    }

    public void setDelegate(PollCreateActivityDelegate pollCreateActivityDelegate) {
        this.delegate = pollCreateActivityDelegate;
    }

    private void showEditDoneProgress(final boolean show) {
        AnimatorSet animatorSet = this.doneItemAnimation;
        if (animatorSet != null) {
            animatorSet.cancel();
        }
        this.doneItemAnimation = new AnimatorSet();
        if (show) {
            this.progressView.setVisibility(0);
            this.doneItem.setEnabled(false);
            this.doneItemAnimation.playTogether(ObjectAnimator.ofFloat(this.doneItem.getContentView(), (Property<View, Float>) View.SCALE_X, 0.1f), ObjectAnimator.ofFloat(this.doneItem.getContentView(), (Property<View, Float>) View.SCALE_Y, 0.1f), ObjectAnimator.ofFloat(this.doneItem.getContentView(), (Property<View, Float>) View.ALPHA, 0.0f), ObjectAnimator.ofFloat(this.progressView, (Property<ContextProgressView, Float>) View.SCALE_X, 1.0f), ObjectAnimator.ofFloat(this.progressView, (Property<ContextProgressView, Float>) View.SCALE_Y, 1.0f), ObjectAnimator.ofFloat(this.progressView, (Property<ContextProgressView, Float>) View.ALPHA, 1.0f));
        } else {
            this.doneItem.getContentView().setVisibility(0);
            this.doneItem.setEnabled(true);
            this.doneItemAnimation.playTogether(ObjectAnimator.ofFloat(this.progressView, (Property<ContextProgressView, Float>) View.SCALE_X, 0.1f), ObjectAnimator.ofFloat(this.progressView, (Property<ContextProgressView, Float>) View.SCALE_Y, 0.1f), ObjectAnimator.ofFloat(this.progressView, (Property<ContextProgressView, Float>) View.ALPHA, 0.0f), ObjectAnimator.ofFloat(this.doneItem.getContentView(), (Property<View, Float>) View.SCALE_X, 1.0f), ObjectAnimator.ofFloat(this.doneItem.getContentView(), (Property<View, Float>) View.SCALE_Y, 1.0f), ObjectAnimator.ofFloat(this.doneItem.getContentView(), (Property<View, Float>) View.ALPHA, 1.0f));
        }
        this.doneItemAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.PollCreateActivity.3
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                if (PollCreateActivity.this.doneItemAnimation != null && PollCreateActivity.this.doneItemAnimation.equals(animation)) {
                    if (!show) {
                        PollCreateActivity.this.progressView.setVisibility(4);
                    } else {
                        PollCreateActivity.this.doneItem.getContentView().setVisibility(4);
                    }
                }
            }

            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationCancel(Animator animation) {
                if (PollCreateActivity.this.doneItemAnimation != null && PollCreateActivity.this.doneItemAnimation.equals(animation)) {
                    PollCreateActivity.this.doneItemAnimation = null;
                }
            }
        });
        this.doneItemAnimation.setDuration(150L);
        this.doneItemAnimation.start();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setTextLeft(View cell, int index) {
        boolean z = cell instanceof HeaderCell;
        String key = Theme.key_windowBackgroundWhiteRedText5;
        if (z) {
            HeaderCell headerCell = (HeaderCell) cell;
            if (index == -1) {
                String str = this.questionString;
                int left = 255 - (str != null ? str.length() : 0);
                if (left <= 76.5f) {
                    headerCell.setText2(String.format("%d", Integer.valueOf(left)));
                    SimpleTextView textView = headerCell.getTextView2();
                    if (left >= 0) {
                        key = Theme.key_windowBackgroundWhiteGrayText3;
                    }
                    textView.setTextColor(Theme.getColor(key));
                    textView.setTag(key);
                    return;
                }
                headerCell.setText2("");
                return;
            }
            headerCell.setText2("");
            return;
        }
        if ((cell instanceof PollEditTextCell) && index >= 0) {
            PollEditTextCell textCell = (PollEditTextCell) cell;
            String[] strArr = this.answers;
            int left2 = 100 - (strArr[index] != null ? strArr[index].length() : 0);
            if (left2 <= 30.0f) {
                textCell.setText2(String.format("%d", Integer.valueOf(left2)));
                SimpleTextView textView2 = textCell.getTextView2();
                if (left2 >= 0) {
                    key = Theme.key_windowBackgroundWhiteGrayText3;
                }
                textView2.setTextColor(Theme.getColor(key));
                textView2.setTag(key);
                return;
            }
            textCell.setText2("");
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void addNewField() {
        int i = this.answersCount + 1;
        this.answersCount = i;
        if (i == this.answers.length) {
            this.listAdapter.notifyItemRemoved(this.addAnswerRow);
        }
        this.listAdapter.notifyItemInserted(this.addAnswerRow);
        updateRows();
        this.requestFieldFocusAtPosition = (this.answerStartRow + this.answersCount) - 1;
        this.listAdapter.notifyItemChanged(this.answerSectionRow);
    }

    /* JADX INFO: Access modifiers changed from: private */
    class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        public ListAdapter(Context context) {
            this.mContext = context;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            return PollCreateActivity.this.rowCount;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            int itemViewType = holder.getItemViewType();
            if (itemViewType == 0) {
                HeaderCell cell = (HeaderCell) holder.itemView;
                if (position != PollCreateActivity.this.questionHeaderRow) {
                    if (position == PollCreateActivity.this.answerHeaderRow) {
                        cell.setText(LocaleController.getString("PollOptions", R.string.PollOptions));
                        return;
                    }
                    return;
                }
                cell.setText(LocaleController.getString("Question", R.string.Question));
                return;
            }
            if (itemViewType == 2) {
                TextInfoPrivacyCell cell2 = (TextInfoPrivacyCell) holder.itemView;
                cell2.setBackgroundDrawable(Theme.getThemedDrawable(this.mContext, R.drawable.greydivider_bottom, Theme.key_windowBackgroundGrayShadow));
                if (10 - PollCreateActivity.this.answersCount <= 0) {
                    cell2.setText(LocaleController.getString("AddAnOptionInfoMax", R.string.AddAnOptionInfoMax));
                    return;
                } else {
                    cell2.setText(LocaleController.formatString("AddAnOptionInfo", R.string.AddAnOptionInfo, LocaleController.formatPluralString("Option", 10 - PollCreateActivity.this.answersCount)));
                    return;
                }
            }
            if (itemViewType == 3) {
                TextSettingsCell textCell = (TextSettingsCell) holder.itemView;
                textCell.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteHintText));
                textCell.setText(LocaleController.getString("AddAnOption", R.string.AddAnOption), false);
                return;
            }
            if (itemViewType == 4) {
                PollEditTextCell textCell2 = (PollEditTextCell) holder.itemView;
                textCell2.setTag(1);
                textCell2.setTextAndHint(PollCreateActivity.this.questionString != null ? PollCreateActivity.this.questionString : "", LocaleController.getString("QuestionHint", R.string.QuestionHint), false);
                textCell2.setTag(null);
                return;
            }
            if (itemViewType == 5) {
                PollEditTextCell textCell3 = (PollEditTextCell) holder.itemView;
                textCell3.setTag(1);
                int index = position - PollCreateActivity.this.answerStartRow;
                textCell3.setTextAndHint(PollCreateActivity.this.answers[index], LocaleController.getString("OptionHint", R.string.OptionHint), true);
                textCell3.setTag(null);
                if (PollCreateActivity.this.requestFieldFocusAtPosition == position) {
                    EditTextBoldCursor editText = textCell3.getTextView();
                    editText.requestFocus();
                    AndroidUtilities.showKeyboard(editText);
                    PollCreateActivity.this.requestFieldFocusAtPosition = -1;
                }
                PollCreateActivity.this.setTextLeft(holder.itemView, position - PollCreateActivity.this.answerStartRow);
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onViewAttachedToWindow(RecyclerView.ViewHolder holder) {
            int viewType = holder.getItemViewType();
            if (viewType == 0 || viewType == 5) {
                PollCreateActivity.this.setTextLeft(holder.itemView, holder.getAdapterPosition() == PollCreateActivity.this.questionHeaderRow ? -1 : 0);
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return holder.getAdapterPosition() == PollCreateActivity.this.addAnswerRow;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup viewGroup, int i) {
            View shadowSectionCell;
            if (i == 0) {
                HeaderCell headerCell = new HeaderCell(this.mContext, false, 21, 15, true);
                headerCell.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                shadowSectionCell = headerCell;
            } else if (i == 1) {
                shadowSectionCell = new ShadowSectionCell(this.mContext);
            } else if (i == 2) {
                shadowSectionCell = new TextInfoPrivacyCell(this.mContext);
            } else if (i == 3) {
                TextSettingsCell textSettingsCell = new TextSettingsCell(this.mContext);
                textSettingsCell.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                shadowSectionCell = textSettingsCell;
            } else if (i == 4) {
                final PollEditTextCell pollEditTextCell = new PollEditTextCell(this.mContext, null);
                pollEditTextCell.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                pollEditTextCell.addTextWatcher(new TextWatcher() { // from class: im.uwrkaxlmjj.ui.PollCreateActivity.ListAdapter.1
                    @Override // android.text.TextWatcher
                    public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                    }

                    @Override // android.text.TextWatcher
                    public void onTextChanged(CharSequence s, int start, int before, int count) {
                    }

                    @Override // android.text.TextWatcher
                    public void afterTextChanged(Editable s) {
                        if (pollEditTextCell.getTag() != null) {
                            return;
                        }
                        PollCreateActivity.this.questionString = s.toString();
                        RecyclerView.ViewHolder holder = PollCreateActivity.this.listView.findViewHolderForAdapterPosition(PollCreateActivity.this.questionHeaderRow);
                        if (holder != null) {
                            PollCreateActivity.this.setTextLeft(holder.itemView, -1);
                        }
                        PollCreateActivity.this.checkDoneButton();
                    }
                });
                shadowSectionCell = pollEditTextCell;
            } else {
                final PollEditTextCell pollEditTextCell2 = new PollEditTextCell(this.mContext, new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PollCreateActivity$ListAdapter$oPhmYDPadY_YHz280W5pvZlDXzE
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view) {
                        this.f$0.lambda$onCreateViewHolder$0$PollCreateActivity$ListAdapter(view);
                    }
                }) { // from class: im.uwrkaxlmjj.ui.PollCreateActivity.ListAdapter.2
                    @Override // im.uwrkaxlmjj.ui.cells.PollEditTextCell
                    protected boolean drawDivider() {
                        RecyclerView.ViewHolder holder = PollCreateActivity.this.listView.findContainingViewHolder(this);
                        if (holder != null) {
                            int position = holder.getAdapterPosition();
                            if (PollCreateActivity.this.answersCount == 10 && position == (PollCreateActivity.this.answerStartRow + PollCreateActivity.this.answersCount) - 1) {
                                return false;
                            }
                        }
                        return true;
                    }
                };
                pollEditTextCell2.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                pollEditTextCell2.addTextWatcher(new TextWatcher() { // from class: im.uwrkaxlmjj.ui.PollCreateActivity.ListAdapter.3
                    @Override // android.text.TextWatcher
                    public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                    }

                    @Override // android.text.TextWatcher
                    public void onTextChanged(CharSequence s, int start, int before, int count) {
                    }

                    @Override // android.text.TextWatcher
                    public void afterTextChanged(Editable s) {
                        RecyclerView.ViewHolder holder = PollCreateActivity.this.listView.findContainingViewHolder(pollEditTextCell2);
                        if (holder != null) {
                            int position = holder.getAdapterPosition();
                            int index = position - PollCreateActivity.this.answerStartRow;
                            if (index >= 0 && index < PollCreateActivity.this.answers.length) {
                                PollCreateActivity.this.answers[index] = s.toString();
                                PollCreateActivity.this.setTextLeft(pollEditTextCell2, index);
                                PollCreateActivity.this.checkDoneButton();
                            }
                        }
                    }
                });
                pollEditTextCell2.setShowNextButton(true);
                EditTextBoldCursor textView = pollEditTextCell2.getTextView();
                textView.setImeOptions(textView.getImeOptions() | 5);
                textView.setOnEditorActionListener(new TextView.OnEditorActionListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PollCreateActivity$ListAdapter$QNXbs_tXxEGP_JVGR41f4cTX9tw
                    @Override // android.widget.TextView.OnEditorActionListener
                    public final boolean onEditorAction(TextView textView2, int i2, KeyEvent keyEvent) {
                        return this.f$0.lambda$onCreateViewHolder$1$PollCreateActivity$ListAdapter(pollEditTextCell2, textView2, i2, keyEvent);
                    }
                });
                textView.setOnKeyListener(new View.OnKeyListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PollCreateActivity$ListAdapter$mwLopj-1Kkdf5oEmIKKjT53U9-4
                    @Override // android.view.View.OnKeyListener
                    public final boolean onKey(View view, int i2, KeyEvent keyEvent) {
                        return PollCreateActivity.ListAdapter.lambda$onCreateViewHolder$2(pollEditTextCell2, view, i2, keyEvent);
                    }
                });
                shadowSectionCell = pollEditTextCell2;
            }
            shadowSectionCell.setLayoutParams(new RecyclerView.LayoutParams(-1, -2));
            return new RecyclerListView.Holder(shadowSectionCell);
        }

        public /* synthetic */ void lambda$onCreateViewHolder$0$PollCreateActivity$ListAdapter(View v) {
            if (v.getTag() != null) {
                return;
            }
            v.setTag(1);
            RecyclerView.ViewHolder holder = PollCreateActivity.this.listView.findContainingViewHolder((View) v.getParent());
            if (holder != null) {
                int position = holder.getAdapterPosition();
                int index = position - PollCreateActivity.this.answerStartRow;
                PollCreateActivity.this.listAdapter.notifyItemRemoved(holder.getAdapterPosition());
                System.arraycopy(PollCreateActivity.this.answers, index + 1, PollCreateActivity.this.answers, index, (PollCreateActivity.this.answers.length - 1) - index);
                PollCreateActivity.this.answers[PollCreateActivity.this.answers.length - 1] = null;
                PollCreateActivity.access$1410(PollCreateActivity.this);
                if (PollCreateActivity.this.answersCount == PollCreateActivity.this.answers.length - 1) {
                    PollCreateActivity.this.listAdapter.notifyItemInserted((PollCreateActivity.this.answerStartRow + PollCreateActivity.this.answers.length) - 1);
                }
                RecyclerView.ViewHolder holder2 = PollCreateActivity.this.listView.findViewHolderForAdapterPosition(position - 1);
                if (holder2 != null && (holder2.itemView instanceof PollEditTextCell)) {
                    PollEditTextCell editTextCell = (PollEditTextCell) holder2.itemView;
                    editTextCell.getTextView().requestFocus();
                }
                PollCreateActivity.this.checkDoneButton();
                PollCreateActivity.this.updateRows();
                PollCreateActivity.this.listAdapter.notifyItemChanged(PollCreateActivity.this.answerSectionRow);
            }
        }

        public /* synthetic */ boolean lambda$onCreateViewHolder$1$PollCreateActivity$ListAdapter(PollEditTextCell cell, TextView v, int actionId, KeyEvent event) {
            if (actionId == 5) {
                RecyclerView.ViewHolder holder = PollCreateActivity.this.listView.findContainingViewHolder(cell);
                if (holder != null) {
                    int position = holder.getAdapterPosition();
                    int index = position - PollCreateActivity.this.answerStartRow;
                    if (index == PollCreateActivity.this.answersCount - 1 && PollCreateActivity.this.answersCount < 10) {
                        PollCreateActivity.this.addNewField();
                    } else if (index != PollCreateActivity.this.answersCount - 1) {
                        RecyclerView.ViewHolder holder2 = PollCreateActivity.this.listView.findViewHolderForAdapterPosition(position + 1);
                        if (holder2 != null && (holder2.itemView instanceof PollEditTextCell)) {
                            PollEditTextCell editTextCell = (PollEditTextCell) holder2.itemView;
                            editTextCell.getTextView().requestFocus();
                        }
                    } else {
                        AndroidUtilities.hideKeyboard(cell.getTextView());
                    }
                }
                return true;
            }
            return false;
        }

        static /* synthetic */ boolean lambda$onCreateViewHolder$2(PollEditTextCell cell, View v, int keyCode, KeyEvent event) {
            EditTextBoldCursor field = (EditTextBoldCursor) v;
            if (keyCode == 67 && event.getAction() == 0 && field.length() == 0) {
                cell.callOnDelete();
                return true;
            }
            return false;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            if (position != PollCreateActivity.this.questionHeaderRow && position != PollCreateActivity.this.answerHeaderRow) {
                if (position != PollCreateActivity.this.questionSectionRow) {
                    if (position != PollCreateActivity.this.answerSectionRow) {
                        if (position != PollCreateActivity.this.addAnswerRow) {
                            if (position == PollCreateActivity.this.questionRow) {
                                return 4;
                            }
                            return 5;
                        }
                        return 3;
                    }
                    return 2;
                }
                return 1;
            }
            return 0;
        }

        public void swapElements(int fromIndex, int toIndex) {
            int idx1 = fromIndex - PollCreateActivity.this.answerStartRow;
            int idx2 = toIndex - PollCreateActivity.this.answerStartRow;
            if (idx1 >= 0 && idx2 >= 0 && idx1 < PollCreateActivity.this.answersCount && idx2 < PollCreateActivity.this.answersCount) {
                String from = PollCreateActivity.this.answers[idx1];
                PollCreateActivity.this.answers[idx1] = PollCreateActivity.this.answers[idx2];
                PollCreateActivity.this.answers[idx2] = from;
                notifyItemMoved(fromIndex, toIndex);
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        return new ThemeDescription[]{new ThemeDescription(this.listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{HeaderCell.class, TextSettingsCell.class, PollEditTextCell.class}, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundGray), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.listView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector), new ThemeDescription(this.listView, 0, new Class[]{HeaderCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlueHeader), new ThemeDescription(this.listView, ThemeDescription.FLAG_CHECKTAG, new Class[]{HeaderCell.class}, new String[]{"textView2"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteRedText5), new ThemeDescription(this.listView, ThemeDescription.FLAG_CHECKTAG, new Class[]{HeaderCell.class}, new String[]{"textView2"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText3), new ThemeDescription(this.listView, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{PollEditTextCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText), new ThemeDescription(this.listView, ThemeDescription.FLAG_HINTTEXTCOLOR, new Class[]{PollEditTextCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteHintText), new ThemeDescription(this.listView, ThemeDescription.FLAG_HINTTEXTCOLOR, new Class[]{PollEditTextCell.class}, new String[]{"deleteImageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText), new ThemeDescription(this.listView, ThemeDescription.FLAG_USEBACKGROUNDDRAWABLE | ThemeDescription.FLAG_DRAWABLESELECTEDSTATE, new Class[]{PollEditTextCell.class}, new String[]{"deleteImageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_stickers_menuSelector), new ThemeDescription(this.listView, ThemeDescription.FLAG_CHECKTAG, new Class[]{PollEditTextCell.class}, new String[]{"textView2"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteRedText5), new ThemeDescription(this.listView, ThemeDescription.FLAG_CHECKTAG, new Class[]{PollEditTextCell.class}, new String[]{"textView2"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText3), new ThemeDescription(this.listView, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.listView, 0, new Class[]{View.class}, Theme.dividerPaint, null, null, Theme.key_divider), new ThemeDescription(this.listView, 0, new Class[]{TextSettingsCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteHintText)};
    }
}
