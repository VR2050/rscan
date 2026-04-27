package im.uwrkaxlmjj.ui.adapters;

import android.content.Context;
import android.util.SparseArray;
import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.cells.GraySectionCell;
import im.uwrkaxlmjj.ui.cells.LetterSectionCell;
import im.uwrkaxlmjj.ui.cells.TextCell;
import im.uwrkaxlmjj.ui.cells.UserCell;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class ContactsAdapter extends RecyclerListView.SectionsAdapter {
    private SparseArray<?> checkedMap;
    private int currentAccount = UserConfig.selectedAccount;
    private boolean disableSections;
    private boolean hasGps;
    private SparseArray<TLRPC.User> ignoreUsers;
    private boolean isAdmin;
    private boolean isChannel;
    private Context mContext;
    private boolean needPhonebook;
    private ArrayList<TLRPC.Contact> onlineContacts;
    private int onlyUsers;
    private boolean scrolling;
    private int sortType;

    public ContactsAdapter(Context context, int onlyUsersType, boolean arg2, SparseArray<TLRPC.User> arg3, int arg4, boolean gps) {
        this.mContext = context;
        this.onlyUsers = onlyUsersType;
        this.needPhonebook = arg2;
        this.ignoreUsers = arg3;
        this.isAdmin = arg4 != 0;
        this.isChannel = arg4 == 2;
        this.hasGps = gps;
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

    public void sortOnlineContacts() {
        if (this.onlineContacts == null) {
            return;
        }
        try {
            final int currentTime = ConnectionsManager.getInstance(this.currentAccount).getCurrentTime();
            final MessagesController messagesController = MessagesController.getInstance(this.currentAccount);
            Collections.sort(this.onlineContacts, new Comparator() { // from class: im.uwrkaxlmjj.ui.adapters.-$$Lambda$ContactsAdapter$u1TRac5JXuOxT6PMHCmZYncfqaY
                @Override // java.util.Comparator
                public final int compare(Object obj, Object obj2) {
                    return ContactsAdapter.lambda$sortOnlineContacts$0(messagesController, currentTime, (TLRPC.Contact) obj, (TLRPC.Contact) obj2);
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
        HashMap<String, ArrayList<TLRPC.Contact>> usersSectionsDict = this.onlyUsers == 2 ? ContactsController.getInstance(this.currentAccount).usersMutualSectionsDict : ContactsController.getInstance(this.currentAccount).usersSectionsDict;
        ArrayList<String> sortedUsersSectionsArray = this.onlyUsers == 2 ? ContactsController.getInstance(this.currentAccount).sortedUsersMutualSectionsArray : ContactsController.getInstance(this.currentAccount).sortedUsersSectionsArray;
        if (this.onlyUsers != 0 && !this.isAdmin) {
            if (section < sortedUsersSectionsArray.size()) {
                ArrayList<TLRPC.Contact> arr = usersSectionsDict.get(sortedUsersSectionsArray.get(section));
                if (position < arr.size()) {
                    return MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(arr.get(position).user_id));
                }
            }
            return null;
        }
        if (section == 0) {
            return null;
        }
        if (this.sortType == 2) {
            if (section == 1) {
                if (position < this.onlineContacts.size()) {
                    return MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(this.onlineContacts.get(position).user_id));
                }
                return null;
            }
        } else if (section - 1 < sortedUsersSectionsArray.size()) {
            ArrayList<TLRPC.Contact> arr2 = usersSectionsDict.get(sortedUsersSectionsArray.get(section - 1));
            if (position < arr2.size()) {
                return MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(arr2.get(position).user_id));
            }
            return null;
        }
        if (this.needPhonebook) {
            return ContactsController.getInstance(this.currentAccount).phoneBookContacts.get(position);
        }
        return null;
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
    public boolean isEnabled(int section, int row) {
        HashMap<String, ArrayList<TLRPC.Contact>> usersSectionsDict = this.onlyUsers == 2 ? ContactsController.getInstance(this.currentAccount).usersMutualSectionsDict : ContactsController.getInstance(this.currentAccount).usersSectionsDict;
        ArrayList<String> sortedUsersSectionsArray = this.onlyUsers == 2 ? ContactsController.getInstance(this.currentAccount).sortedUsersMutualSectionsArray : ContactsController.getInstance(this.currentAccount).sortedUsersSectionsArray;
        if (this.onlyUsers != 0 && !this.isAdmin) {
            ArrayList<TLRPC.Contact> arr = usersSectionsDict.get(sortedUsersSectionsArray.get(section));
            return row < arr.size();
        }
        if (section == 0) {
            return this.isAdmin ? row != 1 : this.needPhonebook ? (this.hasGps && row != 2) || !(this.hasGps || row == 1) : row != 3;
        }
        if (this.sortType == 2) {
            return section != 1 || row < this.onlineContacts.size();
        }
        if (section - 1 < sortedUsersSectionsArray.size()) {
            ArrayList<TLRPC.Contact> arr2 = usersSectionsDict.get(sortedUsersSectionsArray.get(section - 1));
            return row < arr2.size();
        }
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
    public int getSectionCount() {
        int count;
        if (this.sortType == 2) {
            count = 1;
        } else {
            int count2 = this.onlyUsers;
            ArrayList<String> sortedUsersSectionsArray = count2 == 2 ? ContactsController.getInstance(this.currentAccount).sortedUsersMutualSectionsArray : ContactsController.getInstance(this.currentAccount).sortedUsersSectionsArray;
            count = sortedUsersSectionsArray.size();
        }
        if (this.onlyUsers == 0) {
            count++;
        }
        if (this.isAdmin) {
            return count + 1;
        }
        return count;
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
    public int getCountForSection(int section) {
        ArrayList<TLRPC.Contact> arr;
        ArrayList<TLRPC.Contact> arr2;
        HashMap<String, ArrayList<TLRPC.Contact>> usersSectionsDict = this.onlyUsers == 2 ? ContactsController.getInstance(this.currentAccount).usersMutualSectionsDict : ContactsController.getInstance(this.currentAccount).usersSectionsDict;
        ArrayList<String> sortedUsersSectionsArray = this.onlyUsers == 2 ? ContactsController.getInstance(this.currentAccount).sortedUsersMutualSectionsArray : ContactsController.getInstance(this.currentAccount).sortedUsersSectionsArray;
        if (this.onlyUsers != 0 && !this.isAdmin) {
            if (section < sortedUsersSectionsArray.size() && (arr2 = usersSectionsDict.get(sortedUsersSectionsArray.get(section))) != null) {
                int count = arr2.size();
                if (section != sortedUsersSectionsArray.size() - 1 || this.needPhonebook) {
                    return count + 1;
                }
                return count;
            }
        } else {
            if (section == 0) {
                if (this.isAdmin) {
                    return 2;
                }
                if (this.needPhonebook) {
                    return this.hasGps ? 3 : 2;
                }
                return 4;
            }
            if (this.sortType == 2) {
                if (section == 1) {
                    if (this.onlineContacts.isEmpty()) {
                        return 0;
                    }
                    return this.onlineContacts.size() + 1;
                }
            } else if (section - 1 < sortedUsersSectionsArray.size() && (arr = usersSectionsDict.get(sortedUsersSectionsArray.get(section - 1))) != null) {
                int count2 = arr.size();
                if (section - 1 != sortedUsersSectionsArray.size() - 1 || this.needPhonebook) {
                    return count2 + 1;
                }
                return count2;
            }
        }
        if (this.needPhonebook) {
            return ContactsController.getInstance(this.currentAccount).phoneBookContacts.size();
        }
        return 0;
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
    public View getSectionHeaderView(int section, View view) {
        if (this.onlyUsers == 2) {
            HashMap<String, ArrayList<TLRPC.Contact>> map = ContactsController.getInstance(this.currentAccount).usersMutualSectionsDict;
        } else {
            HashMap<String, ArrayList<TLRPC.Contact>> map2 = ContactsController.getInstance(this.currentAccount).usersSectionsDict;
        }
        ArrayList<String> sortedUsersSectionsArray = this.onlyUsers == 2 ? ContactsController.getInstance(this.currentAccount).sortedUsersMutualSectionsArray : ContactsController.getInstance(this.currentAccount).sortedUsersSectionsArray;
        if (view == null) {
            view = new LetterSectionCell(this.mContext);
        }
        LetterSectionCell cell = (LetterSectionCell) view;
        if (this.sortType == 2 || this.disableSections) {
            cell.setLetter("");
        } else if (this.onlyUsers != 0 && !this.isAdmin) {
            if (section < sortedUsersSectionsArray.size()) {
                cell.setLetter(sortedUsersSectionsArray.get(section));
            } else {
                cell.setLetter("");
            }
        } else if (section != 0 && section - 1 < sortedUsersSectionsArray.size()) {
            cell.setLetter(sortedUsersSectionsArray.get(section - 1));
        } else {
            cell.setLetter("");
        }
        return view;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
        View view;
        if (viewType != 0) {
            if (viewType == 1) {
                view = new TextCell(this.mContext);
            } else if (viewType == 2) {
                view = new GraySectionCell(this.mContext);
            } else {
                view = new View(this.mContext);
            }
        } else {
            view = new UserCell(this.mContext, 58, 1, false);
            view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        }
        return new RecyclerListView.Holder(view);
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
    public void onBindViewHolder(int section, int position, RecyclerView.ViewHolder holder) {
        ArrayList<TLRPC.Contact> arr;
        int itemViewType = holder.getItemViewType();
        if (itemViewType == 0) {
            UserCell userCell = (UserCell) holder.itemView;
            userCell.setAvatarPadding((this.sortType == 2 || this.disableSections) ? 6 : 58);
            if (this.sortType == 2) {
                arr = this.onlineContacts;
            } else {
                HashMap<String, ArrayList<TLRPC.Contact>> usersSectionsDict = this.onlyUsers == 2 ? ContactsController.getInstance(this.currentAccount).usersMutualSectionsDict : ContactsController.getInstance(this.currentAccount).usersSectionsDict;
                ArrayList<String> sortedUsersSectionsArray = this.onlyUsers == 2 ? ContactsController.getInstance(this.currentAccount).sortedUsersMutualSectionsArray : ContactsController.getInstance(this.currentAccount).sortedUsersSectionsArray;
                arr = usersSectionsDict.get(sortedUsersSectionsArray.get(section - ((this.onlyUsers == 0 || this.isAdmin) ? 1 : 0)));
            }
            if (arr != null) {
                TLRPC.User user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(arr.get(position).user_id));
                userCell.setData(user, null, null, 0, (section == getSectionCount() - 1 && position == arr.size() - 1) ? false : true);
                SparseArray<?> sparseArray = this.checkedMap;
                if (sparseArray != null) {
                    userCell.setChecked(sparseArray.indexOfKey(user.id) >= 0, !this.scrolling);
                }
                SparseArray<TLRPC.User> sparseArray2 = this.ignoreUsers;
                if (sparseArray2 != null) {
                    if (sparseArray2.indexOfKey(user.id) >= 0) {
                        userCell.setAlpha(0.5f);
                    } else {
                        userCell.setAlpha(1.0f);
                    }
                }
                if (getItemCount() == 1) {
                    userCell.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                    return;
                }
                if (section == 0 && position == 0) {
                    userCell.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f, Theme.getColor(Theme.key_windowBackgroundWhite)));
                    return;
                } else {
                    if (section == getSectionCount() - 1 && position == arr.size() - 1) {
                        userCell.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                        return;
                    }
                    return;
                }
            }
            return;
        }
        if (itemViewType != 1) {
            if (itemViewType == 2) {
                GraySectionCell sectionCell = (GraySectionCell) holder.itemView;
                int i = this.sortType;
                if (i == 0) {
                    sectionCell.setText(LocaleController.getString("Contacts", R.string.Contacts));
                    return;
                } else if (i == 1) {
                    sectionCell.setText(LocaleController.getString("SortedByName", R.string.SortedByName));
                    return;
                } else {
                    sectionCell.setText(LocaleController.getString("SortedByLastSeen", R.string.SortedByLastSeen));
                    return;
                }
            }
            return;
        }
        TextCell textCell = (TextCell) holder.itemView;
        if (section == 0) {
            if (this.needPhonebook) {
                if (position == 0) {
                    textCell.setTextAndIcon(LocaleController.getString("InviteFriends", R.string.InviteFriends), R.drawable.menu_invite, false);
                    return;
                } else {
                    if (position == 1) {
                        textCell.setTextAndIcon(LocaleController.getString("AddPeopleNearby", R.string.AddPeopleNearby), R.drawable.menu_location, false);
                        return;
                    }
                    return;
                }
            }
            if (this.isAdmin) {
                if (this.isChannel) {
                    textCell.setTextAndIcon(LocaleController.getString("ChannelInviteViaLink", R.string.ChannelInviteViaLink), R.drawable.profile_link, false);
                    return;
                } else {
                    textCell.setTextAndIcon(LocaleController.getString("InviteToGroupByLink", R.string.InviteToGroupByLink), R.drawable.profile_link, false);
                    return;
                }
            }
            if (position == 0) {
                textCell.setTextAndIcon(LocaleController.getString("NewGroup", R.string.NewGroup), R.drawable.menu_groups, false);
                return;
            } else if (position == 1) {
                textCell.setTextAndIcon(LocaleController.getString("NewSecretChat", R.string.NewSecretChat), R.drawable.menu_secret, false);
                return;
            } else {
                if (position == 2) {
                    textCell.setTextAndIcon(LocaleController.getString("NewChannel", R.string.NewChannel), R.drawable.menu_broadcast, false);
                    return;
                }
                return;
            }
        }
        ContactsController.Contact contact = ContactsController.getInstance(this.currentAccount).phoneBookContacts.get(position);
        if (contact.first_name != null && contact.last_name != null) {
            textCell.setText(contact.first_name + " " + contact.last_name, false);
            return;
        }
        if (contact.first_name != null) {
            textCell.setText(contact.first_name, false);
        } else {
            textCell.setText(contact.last_name, false);
        }
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
    public int getItemViewType(int section, int position) {
        ArrayList<TLRPC.Contact> arr;
        HashMap<String, ArrayList<TLRPC.Contact>> usersSectionsDict = this.onlyUsers == 2 ? ContactsController.getInstance(this.currentAccount).usersMutualSectionsDict : ContactsController.getInstance(this.currentAccount).usersSectionsDict;
        ArrayList<String> sortedUsersSectionsArray = this.onlyUsers == 2 ? ContactsController.getInstance(this.currentAccount).sortedUsersMutualSectionsArray : ContactsController.getInstance(this.currentAccount).sortedUsersSectionsArray;
        if (this.onlyUsers != 0 && !this.isAdmin) {
            ArrayList<TLRPC.Contact> arr2 = usersSectionsDict.get(sortedUsersSectionsArray.get(section));
            if (arr2 != null) {
                return position < arr2.size() ? 0 : 3;
            }
        } else if (section == 0) {
            if (this.isAdmin) {
                if (position == 1) {
                    return 2;
                }
            } else if (this.needPhonebook) {
                if ((this.hasGps && position == 2) || (!this.hasGps && position == 1)) {
                    return 2;
                }
            } else if (position == 3) {
                return 2;
            }
        } else if (this.sortType == 2) {
            if (section == 1) {
                return position < this.onlineContacts.size() ? 0 : 3;
            }
        } else if (section - 1 < sortedUsersSectionsArray.size() && (arr = usersSectionsDict.get(sortedUsersSectionsArray.get(section - 1))) != null) {
            return position < arr.size() ? 0 : 3;
        }
        return 1;
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.FastScrollAdapter
    public String getLetter(int position) {
        if (this.sortType == 2) {
            return null;
        }
        ArrayList<String> sortedUsersSectionsArray = this.onlyUsers == 2 ? ContactsController.getInstance(this.currentAccount).sortedUsersMutualSectionsArray : ContactsController.getInstance(this.currentAccount).sortedUsersSectionsArray;
        int section = getSectionForPosition(position);
        if (section == -1) {
            section = sortedUsersSectionsArray.size() - 1;
        }
        if (this.onlyUsers != 0 && !this.isAdmin) {
            if (section >= 0 && section < sortedUsersSectionsArray.size()) {
                return sortedUsersSectionsArray.get(section);
            }
        } else if (section > 0 && section <= sortedUsersSectionsArray.size()) {
            return sortedUsersSectionsArray.get(section - 1);
        }
        return null;
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.FastScrollAdapter
    public int getPositionForScrollProgress(float progress) {
        return (int) (getItemCount() * progress);
    }
}
