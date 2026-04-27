package im.uwrkaxlmjj.ui;

import android.animation.ObjectAnimator;
import android.animation.StateListAnimator;
import android.content.Context;
import android.content.DialogInterface;
import android.graphics.Outline;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.os.Bundle;
import android.text.SpannableString;
import android.text.style.ImageSpan;
import android.util.SparseArray;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewOutlineProvider;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.widget.FrameLayout;
import android.widget.ImageView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.ContactsActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.cells.LoadingCell;
import im.uwrkaxlmjj.ui.cells.LocationCell;
import im.uwrkaxlmjj.ui.cells.ProfileSearchCell;
import im.uwrkaxlmjj.ui.cells.TextInfoPrivacyCell;
import im.uwrkaxlmjj.ui.components.CombinedDrawable;
import im.uwrkaxlmjj.ui.components.EmptyTextProgressView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.voip.VoIPHelper;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
@Deprecated
public class CallLogActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate {
    private static final int TYPE_IN = 1;
    private static final int TYPE_MISSED = 2;
    private static final int TYPE_OUT = 0;
    private EmptyTextProgressView emptyView;
    private boolean endReached;
    private boolean firstLoaded;
    private ImageView floatingButton;
    private boolean floatingHidden;
    private Drawable greenDrawable;
    private Drawable greenDrawable2;
    private ImageSpan iconIn;
    private ImageSpan iconMissed;
    private ImageSpan iconOut;
    private TLRPC.User lastCallUser;
    private LinearLayoutManager layoutManager;
    private RecyclerListView listView;
    private ListAdapter listViewAdapter;
    private boolean loading;
    private int prevPosition;
    private int prevTop;
    private Drawable redDrawable;
    private boolean scrollUpdated;
    private ArrayList<CallLogRow> calls = new ArrayList<>();
    private final AccelerateDecelerateInterpolator floatingInterpolator = new AccelerateDecelerateInterpolator();
    private View.OnClickListener callBtnClickListener = new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.CallLogActivity.1
        @Override // android.view.View.OnClickListener
        public void onClick(View v) {
            CallLogRow row = (CallLogRow) v.getTag();
            VoIPHelper.startCall(CallLogActivity.this.lastCallUser = row.user, CallLogActivity.this.getParentActivity(), null);
        }
    };

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        ListAdapter listAdapter;
        if (id == NotificationCenter.didReceiveNewMessages && this.firstLoaded) {
            boolean scheduled = ((Boolean) args[2]).booleanValue();
            if (scheduled) {
                return;
            }
            ArrayList<MessageObject> arr = (ArrayList) args[1];
            for (MessageObject msg : arr) {
                if (msg.messageOwner.action instanceof TLRPC.TL_messageActionPhoneCall) {
                    int userID = msg.messageOwner.from_id == UserConfig.getInstance(this.currentAccount).getClientUserId() ? msg.messageOwner.to_id.user_id : msg.messageOwner.from_id;
                    int callType = msg.messageOwner.from_id == UserConfig.getInstance(this.currentAccount).getClientUserId() ? 0 : 1;
                    TLRPC.PhoneCallDiscardReason reason = msg.messageOwner.action.reason;
                    if (callType == 1 && ((reason instanceof TLRPC.TL_phoneCallDiscardReasonMissed) || (reason instanceof TLRPC.TL_phoneCallDiscardReasonBusy))) {
                        callType = 2;
                    }
                    if (this.calls.size() > 0) {
                        CallLogRow topRow = this.calls.get(0);
                        if (topRow.user.id == userID && topRow.type == callType) {
                            topRow.calls.add(0, msg.messageOwner);
                            this.listViewAdapter.notifyItemChanged(0);
                        }
                    }
                    CallLogRow row = new CallLogRow();
                    row.calls = new ArrayList();
                    row.calls.add(msg.messageOwner);
                    row.user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(userID));
                    row.type = callType;
                    this.calls.add(0, row);
                    this.listViewAdapter.notifyItemInserted(0);
                }
            }
            return;
        }
        if (id == NotificationCenter.messagesDeleted && this.firstLoaded) {
            boolean scheduled2 = ((Boolean) args[2]).booleanValue();
            if (scheduled2) {
                return;
            }
            boolean didChange = false;
            ArrayList<Integer> ids = (ArrayList) args[0];
            Iterator<CallLogRow> itrtr = this.calls.iterator();
            while (itrtr.hasNext()) {
                CallLogRow row2 = itrtr.next();
                Iterator<TLRPC.Message> msgs = row2.calls.iterator();
                while (msgs.hasNext()) {
                    if (ids.contains(Integer.valueOf(msgs.next().id))) {
                        didChange = true;
                        msgs.remove();
                    }
                }
                if (row2.calls.size() == 0) {
                    itrtr.remove();
                }
            }
            if (didChange && (listAdapter = this.listViewAdapter) != null) {
                listAdapter.notifyDataSetChanged();
            }
        }
    }

    private class CustomCell extends FrameLayout {
        private ImageView imageView;
        private ProfileSearchCell profileSearchCell;

        public CustomCell(Context context) {
            super(context);
            setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            ProfileSearchCell profileSearchCell = new ProfileSearchCell(context);
            this.profileSearchCell = profileSearchCell;
            profileSearchCell.setPadding(LocaleController.isRTL ? AndroidUtilities.dp(32.0f) : 0, 0, LocaleController.isRTL ? 0 : AndroidUtilities.dp(32.0f), 0);
            this.profileSearchCell.setSublabelOffset(AndroidUtilities.dp(LocaleController.isRTL ? 2.0f : -2.0f), -AndroidUtilities.dp(4.0f));
            addView(this.profileSearchCell, LayoutHelper.createFrame(-1, -1.0f));
            ImageView imageView = new ImageView(context);
            this.imageView = imageView;
            imageView.setImageResource(R.drawable.profile_phone);
            this.imageView.setAlpha(214);
            this.imageView.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_featuredStickers_addButton), PorterDuff.Mode.MULTIPLY));
            this.imageView.setBackgroundDrawable(Theme.createSelectorDrawable(Theme.getColor(Theme.key_listSelector), 1));
            this.imageView.setScaleType(ImageView.ScaleType.CENTER);
            this.imageView.setOnClickListener(CallLogActivity.this.callBtnClickListener);
            this.imageView.setContentDescription(LocaleController.getString("Call", R.string.Call));
            addView(this.imageView, LayoutHelper.createFrame(48.0f, 48.0f, (LocaleController.isRTL ? 3 : 5) | 16, 8.0f, 0.0f, 8.0f, 0.0f));
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        getCalls(0, 50);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.didReceiveNewMessages);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.messagesDeleted);
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.didReceiveNewMessages);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.messagesDeleted);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        Drawable drawableMutate = getParentActivity().getResources().getDrawable(R.drawable.ic_call_made_green_18dp).mutate();
        this.greenDrawable = drawableMutate;
        drawableMutate.setBounds(0, 0, drawableMutate.getIntrinsicWidth(), this.greenDrawable.getIntrinsicHeight());
        this.greenDrawable.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_calls_callReceivedGreenIcon), PorterDuff.Mode.MULTIPLY));
        this.iconOut = new ImageSpan(this.greenDrawable, 0);
        Drawable drawableMutate2 = getParentActivity().getResources().getDrawable(R.drawable.ic_call_received_green_18dp).mutate();
        this.greenDrawable2 = drawableMutate2;
        drawableMutate2.setBounds(0, 0, drawableMutate2.getIntrinsicWidth(), this.greenDrawable2.getIntrinsicHeight());
        this.greenDrawable2.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_calls_callReceivedGreenIcon), PorterDuff.Mode.MULTIPLY));
        this.iconIn = new ImageSpan(this.greenDrawable2, 0);
        Drawable drawableMutate3 = getParentActivity().getResources().getDrawable(R.drawable.ic_call_received_green_18dp).mutate();
        this.redDrawable = drawableMutate3;
        drawableMutate3.setBounds(0, 0, drawableMutate3.getIntrinsicWidth(), this.redDrawable.getIntrinsicHeight());
        this.redDrawable.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_calls_callReceivedRedIcon), PorterDuff.Mode.MULTIPLY));
        this.iconMissed = new ImageSpan(this.redDrawable, 0);
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setAllowOverlayTitle(true);
        this.actionBar.setTitle(LocaleController.getString("Calls", R.string.Calls));
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.CallLogActivity.2
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    CallLogActivity.this.finishFragment();
                }
            }
        });
        this.fragmentView = new FrameLayout(context);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        FrameLayout frameLayout = (FrameLayout) this.fragmentView;
        EmptyTextProgressView emptyTextProgressView = new EmptyTextProgressView(context);
        this.emptyView = emptyTextProgressView;
        emptyTextProgressView.setText(LocaleController.getString("NoCallLog", R.string.NoCallLog));
        frameLayout.addView(this.emptyView, LayoutHelper.createFrame(-1, -1.0f));
        RecyclerListView recyclerListView = new RecyclerListView(context);
        this.listView = recyclerListView;
        recyclerListView.setEmptyView(this.emptyView);
        RecyclerListView recyclerListView2 = this.listView;
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(context, 1, false);
        this.layoutManager = linearLayoutManager;
        recyclerListView2.setLayoutManager(linearLayoutManager);
        RecyclerListView recyclerListView3 = this.listView;
        ListAdapter listAdapter = new ListAdapter(context);
        this.listViewAdapter = listAdapter;
        recyclerListView3.setAdapter(listAdapter);
        this.listView.setVerticalScrollbarPosition(LocaleController.isRTL ? 1 : 2);
        frameLayout.addView(this.listView, LayoutHelper.createFrame(-1, -1.0f));
        this.listView.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$CallLogActivity$FbnUklsJ6hXvkfEXnvI2wbAN5gI
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$createView$0$CallLogActivity(view, i);
            }
        });
        this.listView.setOnItemLongClickListener(new RecyclerListView.OnItemLongClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$CallLogActivity$y2dU9BeSqVppnRwR5aBdSDU5eCE
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemLongClickListener
            public final boolean onItemClick(View view, int i) {
                return this.f$0.lambda$createView$2$CallLogActivity(view, i);
            }
        });
        this.listView.setOnScrollListener(new AnonymousClass3());
        if (this.loading) {
            this.emptyView.showProgress();
        } else {
            this.emptyView.showTextView();
        }
        ImageView imageView = new ImageView(context);
        this.floatingButton = imageView;
        imageView.setVisibility(0);
        this.floatingButton.setScaleType(ImageView.ScaleType.CENTER);
        Drawable drawable = Theme.createSimpleSelectorCircleDrawable(AndroidUtilities.dp(56.0f), Theme.getColor(Theme.key_chats_actionBackground), Theme.getColor(Theme.key_chats_actionPressedBackground));
        if (Build.VERSION.SDK_INT < 21) {
            Drawable shadowDrawable = context.getResources().getDrawable(R.drawable.floating_shadow).mutate();
            shadowDrawable.setColorFilter(new PorterDuffColorFilter(-16777216, PorterDuff.Mode.MULTIPLY));
            CombinedDrawable combinedDrawable = new CombinedDrawable(shadowDrawable, drawable, 0, 0);
            combinedDrawable.setIconSize(AndroidUtilities.dp(56.0f), AndroidUtilities.dp(56.0f));
            drawable = combinedDrawable;
        }
        this.floatingButton.setBackgroundDrawable(drawable);
        this.floatingButton.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chats_actionIcon), PorterDuff.Mode.MULTIPLY));
        this.floatingButton.setImageResource(R.drawable.ic_call);
        this.floatingButton.setContentDescription(LocaleController.getString("Call", R.string.Call));
        if (Build.VERSION.SDK_INT >= 21) {
            StateListAnimator animator = new StateListAnimator();
            animator.addState(new int[]{android.R.attr.state_pressed}, ObjectAnimator.ofFloat(this.floatingButton, "translationZ", AndroidUtilities.dp(2.0f), AndroidUtilities.dp(4.0f)).setDuration(200L));
            animator.addState(new int[0], ObjectAnimator.ofFloat(this.floatingButton, "translationZ", AndroidUtilities.dp(4.0f), AndroidUtilities.dp(2.0f)).setDuration(200L));
            this.floatingButton.setStateListAnimator(animator);
            this.floatingButton.setOutlineProvider(new ViewOutlineProvider() { // from class: im.uwrkaxlmjj.ui.CallLogActivity.4
                @Override // android.view.ViewOutlineProvider
                public void getOutline(View view, Outline outline) {
                    outline.setOval(0, 0, AndroidUtilities.dp(56.0f), AndroidUtilities.dp(56.0f));
                }
            });
        }
        frameLayout.addView(this.floatingButton, LayoutHelper.createFrame(Build.VERSION.SDK_INT >= 21 ? 56.0f : 60.0f, Build.VERSION.SDK_INT >= 21 ? 56.0f : 60.0f, (LocaleController.isRTL ? 3 : 5) | 80, LocaleController.isRTL ? 14.0f : 0.0f, 0.0f, LocaleController.isRTL ? 0.0f : 14.0f, 14.0f));
        this.floatingButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$CallLogActivity$E1AG1zUJsTYjpRbyNCbboMdDXPg
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$createView$4$CallLogActivity(view);
            }
        });
        return this.fragmentView;
    }

    public /* synthetic */ void lambda$createView$0$CallLogActivity(View view, int position) {
        if (position < 0 || position >= this.calls.size()) {
            return;
        }
        CallLogRow row = this.calls.get(position);
        Bundle args = new Bundle();
        args.putInt("user_id", row.user.id);
        args.putInt("message_id", row.calls.get(0).id);
        NotificationCenter.getInstance(this.currentAccount).postNotificationName(NotificationCenter.closeChats, new Object[0]);
        presentFragment(new ChatActivity(args), true);
    }

    public /* synthetic */ boolean lambda$createView$2$CallLogActivity(View view, int position) {
        if (position < 0 || position >= this.calls.size()) {
            return false;
        }
        final CallLogRow row = this.calls.get(position);
        ArrayList<String> items = new ArrayList<>();
        items.add(LocaleController.getString("Delete", R.string.Delete));
        if (VoIPHelper.canRateCall((TLRPC.TL_messageActionPhoneCall) row.calls.get(0).action)) {
            items.add(LocaleController.getString("CallMessageReportProblem", R.string.CallMessageReportProblem));
        }
        new AlertDialog.Builder(getParentActivity()).setTitle(LocaleController.getString("Calls", R.string.Calls)).setItems((CharSequence[]) items.toArray(new String[0]), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$CallLogActivity$Fqz8fVOe05SF2X6IIT8JOSwWf4k
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$null$1$CallLogActivity(row, dialogInterface, i);
            }
        }).show();
        return true;
    }

    public /* synthetic */ void lambda$null$1$CallLogActivity(CallLogRow row, DialogInterface dialog, int which) {
        if (which == 0) {
            confirmAndDelete(row);
        } else if (which == 1) {
            VoIPHelper.showRateAlert(getParentActivity(), (TLRPC.TL_messageActionPhoneCall) row.calls.get(0).action);
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.CallLogActivity$3, reason: invalid class name */
    class AnonymousClass3 extends RecyclerView.OnScrollListener {
        AnonymousClass3() {
        }

        @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
        public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
            boolean goingDown;
            int firstVisibleItem = CallLogActivity.this.layoutManager.findFirstVisibleItemPosition();
            int visibleItemCount = firstVisibleItem == -1 ? 0 : Math.abs(CallLogActivity.this.layoutManager.findLastVisibleItemPosition() - firstVisibleItem) + 1;
            if (visibleItemCount > 0) {
                int totalItemCount = CallLogActivity.this.listViewAdapter.getItemCount();
                if (!CallLogActivity.this.endReached && !CallLogActivity.this.loading && !CallLogActivity.this.calls.isEmpty() && firstVisibleItem + visibleItemCount >= totalItemCount - 5) {
                    final CallLogRow row = (CallLogRow) CallLogActivity.this.calls.get(CallLogActivity.this.calls.size() - 1);
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$CallLogActivity$3$PKnqnZ36jiaVey5jhppmL-z2IGQ
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$onScrolled$0$CallLogActivity$3(row);
                        }
                    });
                }
            }
            if (CallLogActivity.this.floatingButton.getVisibility() != 8) {
                View topChild = recyclerView.getChildAt(0);
                int firstViewTop = 0;
                if (topChild != null) {
                    firstViewTop = topChild.getTop();
                }
                boolean changed = true;
                if (CallLogActivity.this.prevPosition == firstVisibleItem) {
                    int topDelta = CallLogActivity.this.prevTop - firstViewTop;
                    goingDown = firstViewTop < CallLogActivity.this.prevTop;
                    changed = Math.abs(topDelta) > 1;
                } else {
                    goingDown = firstVisibleItem > CallLogActivity.this.prevPosition;
                }
                if (changed && CallLogActivity.this.scrollUpdated) {
                    CallLogActivity.this.hideFloatingButton(goingDown);
                }
                CallLogActivity.this.prevPosition = firstVisibleItem;
                CallLogActivity.this.prevTop = firstViewTop;
                CallLogActivity.this.scrollUpdated = true;
            }
        }

        public /* synthetic */ void lambda$onScrolled$0$CallLogActivity$3(CallLogRow row) {
            CallLogActivity.this.getCalls(row.calls.get(row.calls.size() - 1).id, 100);
        }
    }

    public /* synthetic */ void lambda$createView$4$CallLogActivity(View v) {
        Bundle args = new Bundle();
        args.putBoolean("destroyAfterSelect", true);
        args.putBoolean("returnAsResult", true);
        args.putBoolean("onlyUsers", true);
        ContactsActivity contactsFragment = new ContactsActivity(args);
        contactsFragment.setDelegate(new ContactsActivity.ContactsActivityDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$CallLogActivity$2GZN0SLWtChimA3rBC0ir-6CPTM
            @Override // im.uwrkaxlmjj.ui.ContactsActivity.ContactsActivityDelegate
            public final void didSelectContact(TLRPC.User user, String str, ContactsActivity contactsActivity) {
                this.f$0.lambda$null$3$CallLogActivity(user, str, contactsActivity);
            }
        });
        presentFragment(contactsFragment);
    }

    public /* synthetic */ void lambda$null$3$CallLogActivity(TLRPC.User user, String param, ContactsActivity activity) {
        VoIPHelper.startCall(user, getParentActivity(), null);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void hideFloatingButton(boolean hide) {
        if (this.floatingHidden == hide) {
            return;
        }
        this.floatingHidden = hide;
        ImageView imageView = this.floatingButton;
        float[] fArr = new float[1];
        fArr[0] = hide ? AndroidUtilities.dp(100.0f) : 0.0f;
        ObjectAnimator animator = ObjectAnimator.ofFloat(imageView, "translationY", fArr).setDuration(300L);
        animator.setInterpolator(this.floatingInterpolator);
        this.floatingButton.setClickable(!hide);
        animator.start();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void getCalls(int max_id, int count) {
        if (this.loading) {
            return;
        }
        this.loading = true;
        EmptyTextProgressView emptyTextProgressView = this.emptyView;
        if (emptyTextProgressView != null && !this.firstLoaded) {
            emptyTextProgressView.showProgress();
        }
        ListAdapter listAdapter = this.listViewAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
        TLRPC.TL_messages_search req = new TLRPC.TL_messages_search();
        req.limit = count;
        req.peer = new TLRPC.TL_inputPeerEmpty();
        req.filter = new TLRPC.TL_inputMessagesFilterPhoneCalls();
        req.q = "";
        req.offset_id = max_id;
        int reqId = ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$CallLogActivity$kAnSPbMu4mSt25ASeUIRaZoaOT0
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$getCalls$6$CallLogActivity(tLObject, tL_error);
            }
        }, 2);
        ConnectionsManager.getInstance(this.currentAccount).bindRequestToGuid(reqId, this.classGuid);
    }

    public /* synthetic */ void lambda$getCalls$6$CallLogActivity(final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$CallLogActivity$zqSp2Ylt5PGzDRLVfMewk7Svwqo
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$5$CallLogActivity(error, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$5$CallLogActivity(TLRPC.TL_error error, TLObject response) {
        CallLogRow currentRow;
        if (error == null) {
            SparseArray<TLRPC.User> users = new SparseArray<>();
            TLRPC.messages_Messages msgs = (TLRPC.messages_Messages) response;
            this.endReached = msgs.messages.isEmpty();
            for (int a = 0; a < msgs.users.size(); a++) {
                TLRPC.User user = msgs.users.get(a);
                users.put(user.id, user);
            }
            if (this.calls.size() > 0) {
                ArrayList<CallLogRow> arrayList = this.calls;
                currentRow = arrayList.get(arrayList.size() - 1);
            } else {
                currentRow = null;
            }
            for (int a2 = 0; a2 < msgs.messages.size(); a2++) {
                TLRPC.Message msg = msgs.messages.get(a2);
                if (msg.action != null && !(msg.action instanceof TLRPC.TL_messageActionHistoryClear)) {
                    int callType = msg.from_id == UserConfig.getInstance(this.currentAccount).getClientUserId() ? 0 : 1;
                    TLRPC.PhoneCallDiscardReason reason = msg.action.reason;
                    if (callType == 1 && ((reason instanceof TLRPC.TL_phoneCallDiscardReasonMissed) || (reason instanceof TLRPC.TL_phoneCallDiscardReasonBusy))) {
                        callType = 2;
                    }
                    int userID = msg.from_id == UserConfig.getInstance(this.currentAccount).getClientUserId() ? msg.to_id.user_id : msg.from_id;
                    if (currentRow == null || currentRow.user.id != userID || currentRow.type != callType) {
                        if (currentRow != null && !this.calls.contains(currentRow)) {
                            this.calls.add(currentRow);
                        }
                        CallLogRow row = new CallLogRow();
                        row.calls = new ArrayList();
                        row.user = users.get(userID);
                        row.type = callType;
                        currentRow = row;
                    }
                    currentRow.calls.add(msg);
                }
            }
            if (currentRow != null && currentRow.calls.size() > 0 && !this.calls.contains(currentRow)) {
                this.calls.add(currentRow);
            }
        } else {
            this.endReached = true;
        }
        this.loading = false;
        this.firstLoaded = true;
        EmptyTextProgressView emptyTextProgressView = this.emptyView;
        if (emptyTextProgressView != null) {
            emptyTextProgressView.showTextView();
        }
        ListAdapter listAdapter = this.listViewAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
    }

    private void confirmAndDelete(final CallLogRow row) {
        if (getParentActivity() == null) {
            return;
        }
        new AlertDialog.Builder(getParentActivity()).setTitle(LocaleController.getString("AppName", R.string.AppName)).setMessage(LocaleController.getString("ConfirmDeleteCallLog", R.string.ConfirmDeleteCallLog)).setPositiveButton(LocaleController.getString("Delete", R.string.Delete), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$CallLogActivity$sqxVZEaxHMh3o4mXRrNi_TeKFV8
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$confirmAndDelete$7$CallLogActivity(row, dialogInterface, i);
            }
        }).setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null).show().setCanceledOnTouchOutside(true);
    }

    public /* synthetic */ void lambda$confirmAndDelete$7$CallLogActivity(CallLogRow row, DialogInterface dialog, int which) {
        ArrayList<Integer> ids = new ArrayList<>();
        for (TLRPC.Message msg : row.calls) {
            ids.add(Integer.valueOf(msg.id));
        }
        MessagesController.getInstance(this.currentAccount).deleteMessages(ids, null, null, 0L, 0, false, false);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        ListAdapter listAdapter = this.listViewAdapter;
        if (listAdapter != null) {
            listAdapter.notifyDataSetChanged();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onRequestPermissionsResultFragment(int requestCode, String[] permissions, int[] grantResults) {
        if (requestCode == 101) {
            if (grantResults.length > 0 && grantResults[0] == 0) {
                VoIPHelper.startCall(this.lastCallUser, getParentActivity(), null);
            } else {
                VoIPHelper.permissionDenied(getParentActivity(), null);
            }
        }
    }

    private class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        public ListAdapter(Context context) {
            this.mContext = context;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return holder.getAdapterPosition() != CallLogActivity.this.calls.size();
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            int count = CallLogActivity.this.calls.size();
            if (!CallLogActivity.this.calls.isEmpty() && !CallLogActivity.this.endReached) {
                return count + 1;
            }
            return count;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup viewGroup, int i) {
            View loadingCell;
            if (i == 0) {
                CustomCell customCell = CallLogActivity.this.new CustomCell(this.mContext);
                customCell.setTag(CallLogActivity.this.new ViewItem(customCell.imageView, customCell.profileSearchCell));
                loadingCell = customCell;
            } else if (i == 1) {
                loadingCell = new LoadingCell(this.mContext);
            } else {
                TextInfoPrivacyCell textInfoPrivacyCell = new TextInfoPrivacyCell(this.mContext);
                textInfoPrivacyCell.setBackgroundDrawable(Theme.getThemedDrawable(this.mContext, R.drawable.greydivider_bottom, Theme.key_windowBackgroundGrayShadow));
                loadingCell = textInfoPrivacyCell;
            }
            return new RecyclerListView.Holder(loadingCell);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            SpannableString subtitle;
            if (holder.getItemViewType() == 0) {
                ViewItem viewItem = (ViewItem) holder.itemView.getTag();
                ProfileSearchCell cell = viewItem.cell;
                CallLogRow row = (CallLogRow) CallLogActivity.this.calls.get(position);
                TLRPC.Message last = row.calls.get(0);
                String ldir = LocaleController.isRTL ? "\u202b" : "";
                if (row.calls.size() == 1) {
                    subtitle = new SpannableString(ldir + "  " + LocaleController.formatDateCallLog(last.date));
                } else {
                    subtitle = new SpannableString(String.format(ldir + "  (%d) %s", Integer.valueOf(row.calls.size()), LocaleController.formatDateCallLog(last.date)));
                }
                int i = row.type;
                if (i == 0) {
                    subtitle.setSpan(CallLogActivity.this.iconOut, ldir.length(), ldir.length() + 1, 0);
                } else if (i == 1) {
                    subtitle.setSpan(CallLogActivity.this.iconIn, ldir.length(), ldir.length() + 1, 0);
                } else if (i == 2) {
                    subtitle.setSpan(CallLogActivity.this.iconMissed, ldir.length(), ldir.length() + 1, 0);
                }
                cell.setData(row.user, null, null, subtitle, false, false);
                cell.useSeparator = (position == CallLogActivity.this.calls.size() + (-1) && CallLogActivity.this.endReached) ? false : true;
                viewItem.button.setTag(row);
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int i) {
            if (i >= CallLogActivity.this.calls.size()) {
                if (!CallLogActivity.this.endReached && i == CallLogActivity.this.calls.size()) {
                    return 1;
                }
                return 2;
            }
            return 0;
        }
    }

    private class ViewItem {
        public ImageView button;
        public ProfileSearchCell cell;

        public ViewItem(ImageView button, ProfileSearchCell cell) {
            this.button = button;
            this.cell = cell;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class CallLogRow {
        public List<TLRPC.Message> calls;
        public int type;
        public TLRPC.User user;

        private CallLogRow() {
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        ThemeDescription.ThemeDescriptionDelegate cellDelegate = new ThemeDescription.ThemeDescriptionDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$CallLogActivity$EOBPlmV4IHUK1V4hYxoP9pzDXQA
            @Override // im.uwrkaxlmjj.ui.actionbar.ThemeDescription.ThemeDescriptionDelegate
            public final void didSetColor() {
                this.f$0.lambda$getThemeDescriptions$8$CallLogActivity();
            }
        };
        return new ThemeDescription[]{new ThemeDescription(this.listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{LocationCell.class, CustomCell.class}, null, null, null, Theme.key_windowBackgroundWhite), new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundGray), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.listView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle), new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector), new ThemeDescription(this.listView, ThemeDescription.FLAG_SELECTOR, null, null, null, null, Theme.key_listSelector), new ThemeDescription(this.listView, 0, new Class[]{View.class}, Theme.dividerPaint, null, null, Theme.key_divider), new ThemeDescription(this.emptyView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_emptyListPlaceholder), new ThemeDescription(this.emptyView, ThemeDescription.FLAG_PROGRESSBAR, null, null, null, null, Theme.key_progressCircle), new ThemeDescription(this.listView, 0, new Class[]{LoadingCell.class}, new String[]{"progressBar"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_progressCircle), new ThemeDescription(this.listView, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{TextInfoPrivacyCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow), new ThemeDescription(this.listView, 0, new Class[]{TextInfoPrivacyCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText4), new ThemeDescription(this.floatingButton, ThemeDescription.FLAG_IMAGECOLOR, null, null, null, null, Theme.key_chats_actionIcon), new ThemeDescription(this.floatingButton, ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_chats_actionBackground), new ThemeDescription(this.floatingButton, ThemeDescription.FLAG_BACKGROUNDFILTER | ThemeDescription.FLAG_DRAWABLESELECTEDSTATE, null, null, null, null, Theme.key_chats_actionPressedBackground), new ThemeDescription(this.listView, 0, new Class[]{CustomCell.class}, new String[]{"imageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_featuredStickers_addButton), new ThemeDescription(this.listView, 0, new Class[]{CustomCell.class}, null, new Drawable[]{Theme.dialogs_verifiedCheckDrawable}, null, Theme.key_chats_verifiedCheck), new ThemeDescription(this.listView, 0, new Class[]{CustomCell.class}, null, new Drawable[]{Theme.dialogs_verifiedDrawable}, null, Theme.key_chats_verifiedBackground), new ThemeDescription(this.listView, 0, new Class[]{CustomCell.class}, Theme.dialogs_offlinePaint, null, null, Theme.key_windowBackgroundWhiteGrayText3), new ThemeDescription(this.listView, 0, new Class[]{CustomCell.class}, Theme.dialogs_onlinePaint, null, null, Theme.key_windowBackgroundWhiteBlueText3), new ThemeDescription(this.listView, 0, new Class[]{CustomCell.class}, (String[]) null, new Paint[]{Theme.dialogs_namePaint, Theme.dialogs_searchNamePaint}, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chats_name), new ThemeDescription(this.listView, 0, new Class[]{CustomCell.class}, (String[]) null, new Paint[]{Theme.dialogs_nameEncryptedPaint, Theme.dialogs_searchNameEncryptedPaint}, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_chats_secretName), new ThemeDescription(this.listView, 0, new Class[]{CustomCell.class}, null, new Drawable[]{Theme.avatar_savedDrawable}, null, Theme.key_avatar_text), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundRed), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundOrange), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundViolet), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundGreen), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundCyan), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundBlue), new ThemeDescription(null, 0, null, null, null, cellDelegate, Theme.key_avatar_backgroundPink), new ThemeDescription(this.listView, 0, new Class[]{View.class}, null, new Drawable[]{this.greenDrawable, this.greenDrawable2, Theme.calllog_msgCallUpRedDrawable, Theme.calllog_msgCallDownRedDrawable}, null, Theme.key_calls_callReceivedGreenIcon), new ThemeDescription(this.listView, 0, new Class[]{View.class}, null, new Drawable[]{this.redDrawable, Theme.calllog_msgCallUpGreenDrawable, Theme.calllog_msgCallDownGreenDrawable}, null, Theme.key_calls_callReceivedRedIcon)};
    }

    public /* synthetic */ void lambda$getThemeDescriptions$8$CallLogActivity() {
        RecyclerListView recyclerListView = this.listView;
        if (recyclerListView != null) {
            int count = recyclerListView.getChildCount();
            for (int a = 0; a < count; a++) {
                View child = this.listView.getChildAt(a);
                if (child instanceof CustomCell) {
                    CustomCell cell = (CustomCell) child;
                    cell.profileSearchCell.update(0);
                }
            }
        }
    }
}
