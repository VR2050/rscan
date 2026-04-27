package im.uwrkaxlmjj.ui.hui.adapter;

import android.content.Context;
import android.graphics.Color;
import android.util.SparseArray;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.cells.LetterSectionCell;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.ColorTextView;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.hcells.UserBoxCell;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class CreateGroupAdapter extends RecyclerListView.SectionsAdapter {
    private SparseArray<?> checkedMap;
    private boolean disableSections;
    private Context mContext;
    private ArrayList<TLRPC.Contact> onlineContacts;
    private boolean scrolling;
    private int sortType;
    private int currentAccount = UserConfig.selectedAccount;
    private boolean needPhonebook = true;
    private int miViewType = 0;

    public CreateGroupAdapter(Context context) {
        this.mContext = context;
    }

    public void setDisableSections(boolean value) {
        this.disableSections = value;
    }

    public void setSortType(int value) {
        this.sortType = value;
        if (value == 2) {
            if (this.onlineContacts == null) {
                this.onlineContacts = new ArrayList<>(ContactsController.getInstance(this.currentAccount).contacts);
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
            }
            sortOnlineContacts();
            return;
        }
        notifyDataSetChanged();
    }

    public void setMiViewType(int miViewType) {
        this.miViewType = miViewType;
    }

    public void sortOnlineContacts() {
        if (this.onlineContacts == null) {
            return;
        }
        try {
            final int currentTime = ConnectionsManager.getInstance(this.currentAccount).getCurrentTime();
            final MessagesController messagesController = MessagesController.getInstance(this.currentAccount);
            Collections.sort(this.onlineContacts, new Comparator() { // from class: im.uwrkaxlmjj.ui.hui.adapter.-$$Lambda$CreateGroupAdapter$cVURQZinNJSt8223trRejlVTZ6U
                @Override // java.util.Comparator
                public final int compare(Object obj, Object obj2) {
                    return CreateGroupAdapter.lambda$sortOnlineContacts$0(messagesController, currentTime, (TLRPC.Contact) obj, (TLRPC.Contact) obj2);
                }
            });
            notifyDataSetChanged();
        } catch (Exception e) {
            FileLog.e(e);
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

    public void setCheckedMap(SparseArray<?> map) {
        this.checkedMap = map;
    }

    public void setIsScrolling(boolean value) {
        this.scrolling = value;
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
    public Object getItem(int section, int position) {
        HashMap<String, ArrayList<TLRPC.Contact>> usersSectionsDict = ContactsController.getInstance(this.currentAccount).usersSectionsDict;
        ArrayList<String> sortedUsersSectionsArray = ContactsController.getInstance(this.currentAccount).sortedUsersSectionsArray;
        if (this.sortType == 2) {
            if (section == 1) {
                if (position < this.onlineContacts.size()) {
                    return MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(this.onlineContacts.get(position).user_id));
                }
                return null;
            }
        } else if (section < sortedUsersSectionsArray.size()) {
            ArrayList<TLRPC.Contact> arr = usersSectionsDict.get(sortedUsersSectionsArray.get(section));
            if (position < arr.size()) {
                return MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(arr.get(position).user_id));
            }
            return null;
        }
        if (this.needPhonebook) {
            return ContactsController.getInstance(this.currentAccount).phoneBookContacts.get(position);
        }
        return null;
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.FastScrollAdapter
    public String getLetter(int position) {
        if (this.sortType == 2) {
            return null;
        }
        ArrayList<String> sortedUsersSectionsArray = ContactsController.getInstance(this.currentAccount).sortedUsersSectionsArray;
        int section = getSectionForPosition(position);
        if (section == -1) {
            section = sortedUsersSectionsArray.size() - 1;
        }
        if (section < 0 || section > sortedUsersSectionsArray.size()) {
            return null;
        }
        return sortedUsersSectionsArray.get(section);
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.FastScrollAdapter
    public int getPositionForScrollProgress(float progress) {
        return (int) (getItemCount() * progress);
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
    public int getSectionCount() {
        ArrayList<String> sortedUsersSectionsArray = ContactsController.getInstance(this.currentAccount).sortedUsersSectionsArray;
        int count = sortedUsersSectionsArray.size();
        return count;
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
    public int getCountForSection(int section) {
        ArrayList<TLRPC.Contact> arr;
        HashMap<String, ArrayList<TLRPC.Contact>> usersSectionsDict = ContactsController.getInstance(this.currentAccount).usersSectionsDict;
        ArrayList<String> sortedUsersSectionsArray = ContactsController.getInstance(this.currentAccount).sortedUsersSectionsArray;
        if (section < sortedUsersSectionsArray.size() && (arr = usersSectionsDict.get(sortedUsersSectionsArray.get(section))) != null) {
            int count = arr.size();
            if (section != sortedUsersSectionsArray.size() - 1 || this.needPhonebook) {
                return count + 1;
            }
            return count;
        }
        if (this.needPhonebook) {
            return ContactsController.getInstance(this.currentAccount).phoneBookContacts.size();
        }
        return 0;
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
    public boolean isEnabled(int section, int row) {
        HashMap<String, ArrayList<TLRPC.Contact>> usersSectionsDict = ContactsController.getInstance(this.currentAccount).usersSectionsDict;
        ArrayList<String> sortedUsersSectionsArray = ContactsController.getInstance(this.currentAccount).sortedUsersSectionsArray;
        if (section >= sortedUsersSectionsArray.size()) {
            return true;
        }
        ArrayList<TLRPC.Contact> arr = usersSectionsDict.get(sortedUsersSectionsArray.get(section));
        return row < arr.size();
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
    public int getItemViewType(int section, int position) {
        HashMap<String, ArrayList<TLRPC.Contact>> usersSectionsDict = ContactsController.getInstance(this.currentAccount).usersSectionsDict;
        ArrayList<String> sortedUsersSectionsArray = ContactsController.getInstance(this.currentAccount).sortedUsersSectionsArray;
        if (section < sortedUsersSectionsArray.size()) {
            ArrayList<TLRPC.Contact> arr = usersSectionsDict.get(sortedUsersSectionsArray.get(section));
            return position < arr.size() ? 0 : 3;
        }
        return 1;
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
    public View getSectionHeaderView(int section, View view) {
        HashMap<String, ArrayList<TLRPC.Contact>> map = ContactsController.getInstance(this.currentAccount).usersSectionsDict;
        ArrayList<String> sortedUsersSectionsArray = ContactsController.getInstance(this.currentAccount).sortedUsersSectionsArray;
        if (view == null) {
            view = new LetterSectionCell(this.mContext);
        }
        LetterSectionCell cell = (LetterSectionCell) view;
        if (section < sortedUsersSectionsArray.size()) {
            cell.setLetter(sortedUsersSectionsArray.get(section));
        } else {
            cell.setLetter("");
        }
        return view;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
        View view;
        if (viewType == 0) {
            if (this.miViewType == 0) {
                view = new UserBoxCell(this.mContext, AndroidUtilities.dp(18.0f), 1, false);
            } else {
                view = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_recently_contacter, parent, false);
            }
        } else {
            view = new View(this.mContext);
        }
        return new RecyclerListView.Holder(view);
    }

    public int getSectionForChar(char section) {
        ArrayList<String> sortedUsersSectionsArray = ContactsController.getInstance(this.currentAccount).sortedUsersSectionsArray;
        for (int i = 0; i <= getSectionCount() - 1; i++) {
            String sortStr = sortedUsersSectionsArray.get(i);
            char firstChar = sortStr.toUpperCase().charAt(0);
            if (firstChar == section) {
                return i;
            }
        }
        return -1;
    }

    public int getPositionForSection(int section) {
        if (section == -1) {
            return -1;
        }
        int positionStart = 0;
        int N = getSectionCount();
        for (int i = 0; i < N; i++) {
            if (i >= section) {
                return positionStart;
            }
            int count = getCountForSection(i);
            positionStart += count;
        }
        return -1;
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
    public void onBindViewHolder(int section, int position, RecyclerView.ViewHolder holder) {
        TLRPC.User user;
        if (holder.getItemViewType() == 0) {
            if (this.miViewType == 0) {
                UserBoxCell userCell = (UserBoxCell) holder.itemView;
                userCell.setAvatarPadding(45);
                HashMap<String, ArrayList<TLRPC.Contact>> usersSectionsDict = ContactsController.getInstance(this.currentAccount).usersSectionsDict;
                ArrayList<String> sortedUsersSectionsArray = ContactsController.getInstance(this.currentAccount).sortedUsersSectionsArray;
                ArrayList<TLRPC.Contact> arr = usersSectionsDict.get(sortedUsersSectionsArray.get(section));
                TLRPC.User user2 = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(arr.get(position).user_id));
                if (section == getSectionCount() - 1 && position == arr.size() - 1) {
                    userCell.setData(user2, null, null, 0);
                    user = user2;
                } else {
                    user = user2;
                    userCell.setData(user2, null, null, 0, true);
                }
                SparseArray<?> sparseArray = this.checkedMap;
                if (sparseArray != null) {
                    userCell.setChecked(sparseArray.indexOfKey(user.id) >= 0, true);
                    return;
                }
                return;
            }
            AvatarDrawable avatarDrawable = new AvatarDrawable();
            ColorTextView tvPersonName = (ColorTextView) holder.itemView.findViewById(R.attr.tv_person_name);
            ColorTextView tvstate = (ColorTextView) holder.itemView.findViewById(R.attr.tv_state);
            BackupImageView iv_Header = (BackupImageView) holder.itemView.findViewById(R.attr.iv_head_img);
            iv_Header.setRoundRadius(AndroidUtilities.dp(7.5f));
            HashMap<String, ArrayList<TLRPC.Contact>> usersSectionsDict2 = ContactsController.getInstance(this.currentAccount).usersSectionsDict;
            ArrayList<String> sortedUsersSectionsArray2 = ContactsController.getInstance(this.currentAccount).sortedUsersSectionsArray;
            TLRPC.User user3 = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(usersSectionsDict2.get(sortedUsersSectionsArray2.get(section)).get(position).user_id));
            tvPersonName.setText(user3.first_name);
            boolean[] booleans = {false};
            tvstate.setText(LocaleController.formatUserStatusNew(this.currentAccount, user3, booleans));
            if (booleans[0]) {
                tvstate.setTextColor(Color.parseColor("#42B71E"));
            } else {
                tvstate.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText2));
            }
            avatarDrawable.setInfo(user3);
            iv_Header.setImage(ImageLocation.getForUser(user3, false), "50_50", avatarDrawable, user3);
        }
    }
}
