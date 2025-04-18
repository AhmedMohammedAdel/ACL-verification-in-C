#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_FILES 10
#define MAX_USERS 5
#define MAX_GROUPS 5

typedef enum {
    NONE = 0,
    READ = 1,
    WRITE = 2,
    EXECUTE = 4
} PermissionBits;

typedef struct {
    int uid;
    char username[20];
} User;

typedef struct {
    int gid;
    char groupname[20];
} Group;

typedef struct {
    int uid;
    int gid;
} UserGroupMapping;

typedef struct {
    int uid;
    int permissions;
} ACLUser;

typedef struct {
    int gid;
    int permissions;
} ACLGroup;

typedef enum {
    TEXT,
    IMAGE,
    AUDIO,
    EXE
} FileType;

typedef struct {
    int owner_permissions;
    int group_permissions;
    int other_permissions;
    ACLUser Add_User[2];
    ACLGroup Add_Group[2];
    int mask;
} ACL;

typedef struct {
    char name[15];
    FileType type;
    time_t createdAt;
    int owner_uid;
    int group_gid;
    ACL acl;
} File;

User users[MAX_USERS] = {
    {100, "ahmed"},
    {101, "Mohammed"},
    {102, "Adel"},
    {103, "Ibrahim"},
    {104, "Mohammed"}
};

Group groups[MAX_GROUPS] = {
    {200, "admin"},
    {201, "staff"},
    {202, "students"},
    {203, "guests"},
    {204, "helloWorld"}
};
UserGroupMapping userGroupMap[MAX_USERS] = {
    {100, 200}, 
    {101, 201}, 
    {102, 202}, 
    {103, 203},
    {104, 204} 
};

int get_gid_by_uid(int uid) {
    for (int i = 0; i < MAX_USERS; i++) {
        if (userGroupMap[i].uid == uid)
            return userGroupMap[i].gid;
    }
    return -1;
}

int is_valid_user(int uid) {
    for (int i = 0; i < MAX_USERS; i++) {
        if (users[i].uid == uid) return 1;
    }
    return 0;
}

int is_valid_group(int gid) {
    for (int i = 0; i < MAX_GROUPS; i++) {
        if (groups[i].gid == gid) return 1;
    }
    return 0;
}

void print_users_and_groups() {
    printf("\nSystem Users:\n");
    for (int i = 0; i < MAX_USERS; i++)
        printf("  UID: %d, Name: %s\n", users[i].uid, users[i].username);

    printf("\nSystem Groups:\n");
    for (int i = 0; i < MAX_GROUPS; i++)
        printf("  GID: %d, Name: %s\n", groups[i].gid, groups[i].groupname);
}

int parse_permissions(char *permissions) {
    int perms = 0;
    if (strchr(permissions, 'r')) perms |= READ;
    if (strchr(permissions, 'w')) perms |= WRITE;
    if (strchr(permissions, 'x')) perms |= EXECUTE;
    return perms;
}

int check_permission(int eUID, int eGID, int requested_perm, File file) {
    ACL acl = file.acl;

    if (eUID == file.owner_uid) {
        if ((acl.owner_permissions & requested_perm) == requested_perm) {
            return 1;
        } else {
            return 0;
        }
    }

    for (int i = 0; i < 2; i++) {
        if (eUID == acl.Add_User[i].uid) {
            if ((acl.Add_User[i].permissions & acl.mask & requested_perm) == requested_perm) {
                return 1;
            } else {
                return 0;
            }
        }
    }

    for (int i = 0; i < 2; i++) {
        if (eGID == acl.Add_Group[i].gid) {
            if ((acl.Add_Group[i].permissions & acl.mask & requested_perm) == requested_perm) {
                return 1;
            } else {
                return 0;
            }
        }
    }

    if (eGID == file.group_gid) {
        if ((acl.group_permissions & requested_perm) == requested_perm) {
            return 1;
        } else {
            return 0;
        }
    }

    if ((acl.other_permissions & requested_perm) == requested_perm) {
        return 1;
    }

    return 0;
}

void print_acl_info(File file) {
    printf("\n-- ACL Info --\n");
    printf("File Name: %s\n", file.name);
    printf("Created At: %s", ctime(&file.createdAt));
    printf("Owner UID: %d\n", file.owner_uid);
    printf("Owner Permissions: %c%c%c\n", 
        (file.acl.owner_permissions & READ) ? 'r' : '-',
        (file.acl.owner_permissions & WRITE) ? 'w' : '-',
        (file.acl.owner_permissions & EXECUTE) ? 'x' : '-');

    printf("Group GID: %d\n", file.group_gid);
    printf("Group Permissions: %c%c%c\n",
        (file.acl.group_permissions & READ) ? 'r' : '-',
        (file.acl.group_permissions & WRITE) ? 'w' : '-',
        (file.acl.group_permissions & EXECUTE) ? 'x' : '-');

    printf("Other Permissions: %c%c%c\n",
        (file.acl.other_permissions & READ) ? 'r' : '-',
        (file.acl.other_permissions & WRITE) ? 'w' : '-',
        (file.acl.other_permissions & EXECUTE) ? 'x' : '-');

    for (int i = 0; i < 2; i++) {
        if (file.acl.Add_User[i].uid != -1) {
            printf("Additional User %d - UID: %d, Perms: %c%c%c\n", i,
                file.acl.Add_User[i].uid,
                (file.acl.Add_User[i].permissions & READ) ? 'r' : '-',
                (file.acl.Add_User[i].permissions & WRITE) ? 'w' : '-',
                (file.acl.Add_User[i].permissions & EXECUTE) ? 'x' : '-');
        }
    }

    for (int i = 0; i < 2; i++) {
        if (file.acl.Add_Group[i].gid != -1) {
            printf("Additional Group %d - GID: %d, Perms: %c%c%c\n", i,
                file.acl.Add_Group[i].gid,
                (file.acl.Add_Group[i].permissions & READ) ? 'r' : '-',
                (file.acl.Add_Group[i].permissions & WRITE) ? 'w' : '-',
                (file.acl.Add_Group[i].permissions & EXECUTE) ? 'x' : '-');
        }
    }

    printf("Mask: %c%c%c\n",
        (file.acl.mask & READ) ? 'r' : '-',
        (file.acl.mask & WRITE) ? 'w' : '-',
        (file.acl.mask & EXECUTE) ? 'x' : '-');
}


void list_files(File files[], int count) {
    printf("\n- Files in the System -\n");
    for (int i = 0; i < count; i++) {
        printf("%d. %s (Created: %s)", i + 1, files[i].name, ctime(&files[i].createdAt));
    }
}

int main() {
    File files[MAX_FILES];
    int fileCount = 0;

    print_users_and_groups();

    printf("\n- Create a File -\n");
    printf("Enter file name: ");
    scanf("%s", files[fileCount].name);

    printf("Enter file type (0=TEXT, 1=IMAGE, 2=AUDIO, 3=EXE): ");
    int type;
    scanf("%d", &type);
    files[fileCount].type = (FileType)type;

    files[fileCount].createdAt = time(NULL);

    printf("Enter owner UID: ");
    int owner_uid;
    scanf("%d", &owner_uid);
    if (!is_valid_user(owner_uid)) {
        printf("Invalid UID!\n");
        return 1;
    }
    files[fileCount].owner_uid = owner_uid;

    int group_gid;
    files[fileCount].group_gid = get_gid_by_uid(owner_uid);
    if (files[fileCount].group_gid == -1) {
        printf("User has no valid group mapping!\n");
        return 1;
        }
        
    files[fileCount].group_gid = group_gid;

    char perms[5];
    printf("Enter owner permissions (rwx): ");
    scanf("%s", perms);
    files[fileCount].acl.owner_permissions = parse_permissions(perms);

    printf("Enter group permissions (rwx): ");
    scanf("%s", perms);
    files[fileCount].acl.group_permissions = parse_permissions(perms);

    printf("Enter other permissions (rwx): ");
    scanf("%s", perms);
    files[fileCount].acl.other_permissions = parse_permissions(perms);

    for (int i = 0; i < 2; i++) {
        files[fileCount].acl.Add_User[i].uid = -1;
        files[fileCount].acl.Add_Group[i].gid = -1;
    }

    printf("\n-- Add Additional Users to ACL --\n");
    for (int i = 0; i < 2; i++) {
        int uid;
        printf("Enter UID for ACL User %d (-1 = skip): ", i + 1);
        scanf("%d", &uid);
        if (uid == -1) break;
        if (!is_valid_user(uid)) {
            printf("Invalid UID!\n");
            i--;
            continue;
        }
        files[fileCount].acl.Add_User[i].uid = uid;

        printf("Enter permissions (rwx): ");
        scanf("%s", perms);
        files[fileCount].acl.Add_User[i].permissions = parse_permissions(perms);
    }

    printf("\n- Add Additional Groups to ACL -\n");
    for (int i = 0; i < 2; i++) {
        int gid;
        printf("Enter GID for ACL Group %d (-1 = skip): ", i + 1);
        scanf("%d", &gid);
        if (gid == -1) break;
        if (!is_valid_group(gid)) {
            printf("Invalid GID!\n");
            i--;
            continue;
        }
        files[fileCount].acl.Add_Group[i].gid = gid;

        printf("Enter permissions (rwx): ");
        scanf("%s", perms);
        files[fileCount].acl.Add_Group[i].permissions = parse_permissions(perms);
    }

    printf("Enter mask permissions (rwx): ");
    scanf("%s", perms);
    files[fileCount].acl.mask = parse_permissions(perms);

    print_acl_info(files[fileCount]);
    fileCount++;

    char choice;
    printf("\nDo you want to know if the system can grant you a permit or not? (y/n): ");
    scanf(" %c", &choice);
    if (choice == 'y') {
        list_files(files, fileCount);

        int index;
        printf("Choose file Number : ");
        scanf("%d", &index);
        index--;

        int test_uid, test_gid;
        printf("Enter UID: ");
        scanf("%d", &test_uid);
        printf("Enter GID: ");
        scanf("%d", &test_gid);
        printf("Enter requested permission (r/w/x): ");
        scanf("%s", perms);

        int req_perm = parse_permissions(perms);

        if (check_permission(test_uid, test_gid, req_perm, files[index])) {
            printf("Access Allowed (granted) ! Ask the administrator to give you permission ^.^ \n");
        } else {
            printf("Access Allowed (denied) !- Request access from someone with higher authority ^-^\n");
        }
    }

    return 0;
}
