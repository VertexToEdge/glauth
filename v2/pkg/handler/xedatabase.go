package handler

import (
	"crypto/md5"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/glauth/v2/pkg/stats"
	"github.com/go-logr/logr"
	_ "github.com/go-sql-driver/mysql"
	"github.com/nmcclain/ldap"
	msgraph "github.com/yaegashi/msgraph.go/v1.0"
)

type xeDatabaseSession struct {
	log    logr.Logger
	dbconn *sql.DB
}
type xeDatabaseHandler struct {
	backend config.Backend
	log     logr.Logger
	session xeDatabaseSession
	lock    *sync.Mutex
}

// global lock for xeDatabaseHandler sessions & servers manipulation
var xeDatabaseLock sync.Mutex

func (h xeDatabaseHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldap.LDAPResultCode, error) {
	bindDN = strings.ToLower(bindDN)
	baseDN := strings.ToLower("," + h.backend.BaseDN)

	h.log.V(6).Info("Bind request", "binddn", bindDN, "basedn", h.backend.BaseDN, "src", conn.RemoteAddr())

	stats.Frontend.Add("bind_reqs", 1)

	// parse the bindDN - ensure that the bindDN ends with the BaseDN
	if !strings.HasSuffix(bindDN, baseDN) {
		h.log.V(2).Info("BindDN not part of our BaseDN", "binddn", bindDN, "basedn", h.backend.BaseDN)
		return ldap.LDAPResultInvalidCredentials, nil
	}
	parts := strings.Split(strings.TrimSuffix(bindDN, baseDN), ",")
	if len(parts) > 2 {
		h.log.V(2).Info("BindDN should have only one or two parts", "binddn", bindDN, "numparts", len(parts))
		return ldap.LDAPResultInvalidCredentials, nil
	}
	userName := strings.TrimPrefix(parts[0], "cn=")

	// try to login
	if s, err := h.session.CheckUserLogin(userName, bindSimplePw); !s {
		h.log.V(2).Info("Login failed", "username", userName, "basedn", h.backend.BaseDN)
		return ldap.LDAPResultInvalidCredentials, err
	}

	stats.Frontend.Add("bind_successes", 1)
	h.log.V(6).Info("Bind success", "binddn", bindDN, "basedn", h.backend.BaseDN, "src", conn.RemoteAddr())
	return ldap.LDAPResultSuccess, nil
}

func (h xeDatabaseHandler) Search(bindDN string, searchReq ldap.SearchRequest, conn net.Conn) (ldap.ServerSearchResult, error) {
	bindDN = strings.ToLower(bindDN)
	baseDN := strings.ToLower("," + h.backend.BaseDN)
	searchBaseDN := strings.ToLower(searchReq.BaseDN)
	h.log.V(6).Info("Search request", "binddn", bindDN, "basedn", baseDN, "src", conn.RemoteAddr(), "filter", searchReq.Filter)
	stats.Frontend.Add("search_reqs", 1)

	// validate the user is authenticated and has appropriate access
	if len(bindDN) < 1 {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInsufficientAccessRights}, fmt.Errorf("search error: Anonymous BindDN not allowed %s", bindDN)
	}
	if !strings.HasSuffix(bindDN, baseDN) {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInsufficientAccessRights}, fmt.Errorf("search error: BindDN %s not in our BaseDN %s", bindDN, h.backend.BaseDN)
	}
	if !strings.HasSuffix(searchBaseDN, h.backend.BaseDN) {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInsufficientAccessRights}, fmt.Errorf("search error: search BaseDN %s is not in our BaseDN %s", searchBaseDN, h.backend.BaseDN)
	}
	// return all users in the config file - the LDAP library will filter results for us
	entries := []*ldap.Entry{}
	filterEntity, err := ldap.GetFilterObjectClass(searchReq.Filter)
	if err != nil {
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("search error: error parsing filter: %s", searchReq.Filter)
	}
	h.lock.Lock()
	session := h.session
	h.lock.Unlock()

	switch filterEntity {
	default:
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("search error: unhandled filter type: %s [%s]", filterEntity, searchReq.Filter)
	case "posixgroup":
		groups, err := session.getGroups()
		if err != nil {
			return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, errors.New("search error: error getting groups")
		}
		for _, g := range groups {
			attrs := []*ldap.EntryAttribute{}
			attrs = append(attrs, &ldap.EntryAttribute{Name: "cn", Values: []string{*g.ID}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "description", Values: []string{fmt.Sprintf("%s from ownCloud", *g.ID)}})
			//			attrs = append(attrs, &ldap.EntryAttribute{"gidNumber", []string{fmt.Sprintf("%d", g.GIDNumber)}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"posixGroup"}})
			if g.Members != nil {
				members := make([]string, len(g.Members))
				for i, v := range g.Members {
					members[i] = *v.ID
				}

				attrs = append(attrs, &ldap.EntryAttribute{Name: "memberUid", Values: members})
			}
			dn := fmt.Sprintf("cn=%s,%s=groups,%s", *g.ID, h.backend.GroupFormat, h.backend.BaseDN)
			entries = append(entries, &ldap.Entry{DN: dn, Attributes: attrs})
		}
	case "posixaccount", "":
		userName := ""
		if searchBaseDN != strings.ToLower(h.backend.BaseDN) {
			parts := strings.Split(strings.TrimSuffix(searchBaseDN, baseDN), ",")
			if len(parts) >= 1 {
				userName = strings.TrimPrefix(parts[0], "cn=")
			}
		}
		users, err := session.getUsers(userName)
		if err != nil {
			h.log.V(6).Info("Could not get user", "username", userName, "err", err)
			return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, errors.New("search error: error getting users")
		}
		for _, u := range users {
			attrs := []*ldap.EntryAttribute{}
			attrs = append(attrs, &ldap.EntryAttribute{Name: "cn", Values: []string{*u.ID}})
			attrs = append(attrs, &ldap.EntryAttribute{Name: "uid", Values: []string{*u.ID}})
			if u.DisplayName != nil {
				attrs = append(attrs, &ldap.EntryAttribute{Name: "givenName", Values: []string{*u.DisplayName}})
			}
			if u.Mail != nil {
				attrs = append(attrs, &ldap.EntryAttribute{Name: "mail", Values: []string{*u.Mail}})
			}

			attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"posixAccount"}})

			attrs = append(attrs, &ldap.EntryAttribute{Name: "description", Values: []string{fmt.Sprintf("%s from Argos", *u.ID)}})

			user_group := h.backend.GroupFormat + "=" + strings.Join(strings.Split(*u.CompanyName, ","), ","+h.backend.GroupFormat+"=")

			for _, v := range strings.Split(*u.CompanyName, ",") {
				attrs = append(attrs, &ldap.EntryAttribute{Name: "ou", Values: []string{v}})
			}

			//fmt.Println(user_group)
			dn := fmt.Sprintf("%s=%s,%s,%s", h.backend.NameFormat, *u.ID, user_group, h.backend.BaseDN)
			entries = append(entries, &ldap.Entry{DN: dn, Attributes: attrs})
		}
	}
	stats.Frontend.Add("search_successes", 1)
	h.log.V(6).Info("AP: Search OK", "filter", searchReq.Filter)
	return ldap.ServerSearchResult{Entries: entries, Referrals: []string{}, Controls: []ldap.Control{}, ResultCode: ldap.LDAPResultSuccess}, nil
}

// Add is not yet supported for the owncloud backend
func (h xeDatabaseHandler) Add(boundDN string, req ldap.AddRequest, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	return ldap.LDAPResultInsufficientAccessRights, nil
}

// Modify is not yet supported for the owncloud backend
func (h xeDatabaseHandler) Modify(boundDN string, req ldap.ModifyRequest, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	return ldap.LDAPResultInsufficientAccessRights, nil
}

// Delete is not yet supported for the owncloud backend
func (h xeDatabaseHandler) Delete(boundDN string, deleteDN string, conn net.Conn) (result ldap.LDAPResultCode, err error) {
	return ldap.LDAPResultInsufficientAccessRights, nil
}

// FindUser with the given username. Called by the ldap backend to authenticate the bind. Optional
func (h xeDatabaseHandler) FindUser(userName string, searchByUPN bool) (found bool, user config.User, err error) {
	return false, config.User{}, nil
}

func (h xeDatabaseHandler) FindGroup(groupName string) (found bool, group config.Group, err error) {
	return false, config.Group{}, nil
}

func (h xeDatabaseHandler) Close(boundDN string, conn net.Conn) error {
	conn.Close() // close connection to the server when then client is closed
	h.lock.Lock()
	defer h.lock.Unlock()
	//h.session.dbconn.Close()
	stats.Frontend.Add("closes", 1)
	stats.Backend.Add("closes", 1)
	return nil
}

func NewXeDatabaseHandler(opts ...Option) Handler {
	options := newOptions(opts...)

	database, err := sql.Open("mysql", options.Backend.XeDatabase.GetSQLConnectionInfo())

	if err != nil {
		panic(err)
	}
	database.SetConnMaxLifetime(time.Minute * 3)
	database.SetMaxOpenConns(10)
	database.SetMaxIdleConns(10)

	session := xeDatabaseSession{}
	session.log = options.Logger
	session.dbconn = database

	return xeDatabaseHandler{
		backend: options.Backend,
		log:     options.Logger,
		session: session,
		lock:    &xeDatabaseLock,
	}
}

func (p *xeDatabaseSession) CheckUserLogin(userid, userpw string) (bool, error) {
	var password_hash string

	if strings.Count(userid, "=") > 0 {
		userid = strings.Split(userid, "=")[1]
	}

	tx, err := p.dbconn.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare("SELECT password FROM xe_member WHERE user_id = ?")
	if err != nil {
		return false, err
	}
	defer stmt.Close()
	err = stmt.QueryRow(userid).Scan(&password_hash)
	if err != nil {
		return false, err
	}
	err = tx.Commit()
	if err != nil {
		return false, err
	}

	return password_hash == fmt.Sprintf("%x", md5.Sum([]byte(userpw))), nil
}
func (p *xeDatabaseSession) getMemberSrl(userid string) (member_srl uint32, err error) {

	tx, err := p.dbconn.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare("SELECT member_srl FROM xe_member WHERE user_id = ?")
	if err != nil {
		return
	}
	defer stmt.Close()
	err = stmt.QueryRow(userid).Scan(&member_srl)
	if err != nil {
		return
	}
	err = tx.Commit()
	if err != nil {
		return
	}
	err = nil
	return
}
func (p *xeDatabaseSession) GetUserGroups(userid string) (groups []string, err error) {

	tx, err := p.dbconn.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare("select xe_member_group.title from xe_member inner join xe_member_group_member on xe_member.member_srl=xe_member_group_member.member_srl and xe_member.user_id=? inner join xe_member_group on xe_member_group.group_srl=xe_member_group_member.group_srl;")
	if err != nil {
		return
	}
	defer stmt.Close()

	rows, err := stmt.Query(userid)

	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var group string
		err = rows.Scan(&group)
		if err != nil {
			return
		}
		groups = append(groups, group)
	}

	err = tx.Commit()
	if err != nil {
		return
	}
	err = nil
	return
}
func (p xeDatabaseSession) getGroups() ([]msgraph.Group, error) {

	tx, err := p.dbconn.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare("select title from xe_member_group;")
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	rows, err := stmt.Query()

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	ret := make([]msgraph.Group, 0)

	for rows.Next() {
		var group_name string
		err = rows.Scan(&group_name)
		if err != nil {
			return nil, err
		}
		ret = append(ret, msgraph.Group{DirectoryObject: msgraph.DirectoryObject{Entity: msgraph.Entity{ID: &group_name}}})
	}

	err = tx.Commit()
	if err != nil {
		return nil, err
	}
	return ret, nil
}
func (s xeDatabaseSession) getUsers(userName string) ([]msgraph.User, error) {

	tx, err := s.dbconn.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare("select xe_member.user_id, xe_member.user_name, LOWER(xe_member.email_address), xe_member.member_srl, group_concat(xe_member_group.title) from xe_member inner join xe_member_group_member on xe_member_group_member.member_srl = xe_member.member_srl inner join xe_member_group on xe_member_group.group_srl = xe_member_group_member.group_srl group by user_id;")
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	rows, err := stmt.Query()

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	ret := make([]msgraph.User, 0)

	for rows.Next() {
		var user_id, user_name, email_address, groups string
		var member_srl uint32
		err = rows.Scan(&user_id, &user_name, &email_address, &member_srl, &groups)
		if err != nil {
			return nil, err
		}

		ret = append(ret, msgraph.User{
			DirectoryObject: msgraph.DirectoryObject{
				Entity: msgraph.Entity{ID: &user_id},
			},
			DisplayName: &user_name,
			Mail:        &email_address,
			CompanyName: &groups,
		})
	}

	err = tx.Commit()
	if err != nil {
		return nil, err
	}
	return ret, nil
}
