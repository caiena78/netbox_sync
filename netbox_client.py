"""
netbox_client.py
================
Production-quality client for the NetBox REST API using pynetbox.

All returned values are plain Python dicts (JSON-serialisable), making
the client immediately usable in n8n, Ansible, or any other automation
platform that needs serialisable data rather than pynetbox Record objects.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import pynetbox
from requests.adapters import HTTPAdapter


# --------------------------------------------------------------------------- #
# Custom exception                                                             #
# --------------------------------------------------------------------------- #


class NetBoxClientError(Exception):
    """Base exception for all NetBoxClient errors."""


# --------------------------------------------------------------------------- #
# Main class                                                                   #
# --------------------------------------------------------------------------- #


class NetBoxClient:
    """
    Client for the NetBox REST API.

    Uses pynetbox as the underlying HTTP layer.  Every record returned by
    pynetbox is automatically converted to a plain ``dict`` so callers
    receive only JSON-serialisable data.

    Parameters
    ----------
    base_url : str
        Full base URL of the NetBox instance, e.g.
        ``"https://netbox.example.org"``.
    token : str
        NetBox API authentication token.
    verify_ssl : bool
        Whether to verify TLS certificates (default ``True``).
    threading : bool
        Enable pynetbox multi-threaded mode (default ``False``).
    strict_filters : bool
        When ``True`` (default), raise ``NetBoxClientError`` for unknown
        filter keys.  Set to ``False`` to pass unknown keys through
        silently (useful while developing against newer NetBox versions).
    log : logging.Logger, optional
        Caller-supplied logger; a module-level logger is used when omitted.
    """

    def __init__(
        self,
        base_url: str,
        token: str,
        verify_ssl: bool = True,
        threading: bool = False,
        strict_filters: bool = True,
        log: Optional[logging.Logger] = None,
        pool_size: int = 20,
    ) -> None:
        self.base_url       = base_url.rstrip("/")
        self.token          = token
        self.verify_ssl     = verify_ssl
        self.threading      = threading
        self.strict_filters = strict_filters
        self.log            = log or logging.getLogger(__name__)

        self.nb = pynetbox.api(self.base_url, token=self.token)
        self.nb.http_session.verify = verify_ssl
        if threading:
            self.nb.threading = True

        # Raise the urllib3 connection pool size so concurrent threads never
        # exhaust the pool and trigger "Connection pool is full" warnings.
        # The default HTTPAdapter pool is 10; with multi-threaded workers that
        # exceeds the limit quickly.  pool_size=20 comfortably covers the
        # default --max-workers=5 with headroom for bursts.
        _adapter = HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size)
        self.nb.http_session.mount("https://", _adapter)
        self.nb.http_session.mount("http://",  _adapter)

    # ----------------------------------------------------------------------- #
    # Device methods                                                           #
    # ----------------------------------------------------------------------- #

    def get_devices(self, filters: Optional[Dict[str, Any]] = None) -> List[dict]:
        """
        Return a list of devices matching *filters*.

        Parameters
        ----------
        filters : dict, optional
            Keyword arguments forwarded to ``nb.dcim.devices.filter()``.
            Examples::

                {"site": "nyc", "status": "active"}
                {"role": "leaf-switch", "has_primary_ip": True}

        Returns
        -------
        list[dict]
            JSON-serialisable list of device records.  Empty list when no
            devices match.

        Raises
        ------
        NetBoxClientError
            On API request failure.
        """
        filters = filters or {}
        self.log.debug("get_devices filters=%s", filters)
        try:
            records = self.nb.dcim.devices.filter(**filters)
            return [self._to_dict(r) for r in records]
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(f"get_devices failed: {exc}") from exc

    def get_device(
        self,
        name: Optional[str] = None,
        id: Optional[int] = None,
    ) -> Optional[dict]:
        """
        Return a single device by name or ID, or ``None`` if not found.

        Exactly one of *name* or *id* must be supplied.

        Parameters
        ----------
        name : str, optional
            Device name (exact, case-sensitive match).
        id : int, optional
            NetBox device primary key.

        Returns
        -------
        dict or None

        Raises
        ------
        NetBoxClientError
            If neither *name* nor *id* is provided, or on API failure.
        """
        if id is not None:
            self.log.debug("get_device id=%s", id)
            try:
                rec = self.nb.dcim.devices.get(id)
                return self._to_dict(rec) if rec else None
            except pynetbox.RequestError as exc:
                raise NetBoxClientError(
                    f"get_device(id={id}) failed: {exc}"
                ) from exc

        if name is not None:
            self.log.debug("get_device name=%r", name)
            try:
                rec = self.nb.dcim.devices.get(name=name)
                return self._to_dict(rec) if rec else None
            except pynetbox.RequestError as exc:
                raise NetBoxClientError(
                    f"get_device(name={name!r}) failed: {exc}"
                ) from exc

        raise NetBoxClientError("get_device requires either name or id.")

    def get_interfaces(
        self,
        device_name: Optional[str] = None,
        device_id: Optional[int] = None,
    ) -> List[dict]:
        """
        Return all interfaces attached to a device.

        Exactly one of *device_name* or *device_id* must be supplied.

        Parameters
        ----------
        device_name : str, optional
            Resolve the device by name, then look up its interfaces.
        device_id : int, optional
            Use device ID directly (skips an extra API round-trip).

        Returns
        -------
        list[dict]
            JSON-serialisable list of interface records.

        Raises
        ------
        NetBoxClientError
            If the device is not found, or on API failure.
        """
        if device_id is None and device_name is None:
            raise NetBoxClientError(
                "get_interfaces requires either device_name or device_id."
            )

        if device_id is None:
            device = self._require_device(device_name=device_name)
            device_id = device["id"]

        self.log.debug("get_interfaces device_id=%s", device_id)
        try:
            records = self.nb.dcim.interfaces.filter(device_id=device_id)
            return [self._to_dict(r) for r in records]
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"get_interfaces(device_id={device_id}) failed: {exc}"
            ) from exc

    # ----------------------------------------------------------------------- #
    # Virtual chassis methods                                                  #
    # ----------------------------------------------------------------------- #

    def find_virtual_chassis(self, name: str) -> Optional[dict]:
        """
        Look up a virtual chassis by exact name.

        Parameters
        ----------
        name : str
            Virtual chassis name.

        Returns
        -------
        dict or None
            Virtual chassis record, or ``None`` if not found.

        Raises
        ------
        NetBoxClientError
            On API failure.
        """
        self.log.debug("find_virtual_chassis name=%r", name)
        try:
            rec = self.nb.dcim.virtual_chassis.get(name=name)
            return self._to_dict(rec) if rec else None
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"Virtual chassis lookup failed for {name!r}: {exc}"
            ) from exc

    def get_virtual_chassis_members(self, vc_id: int) -> List[dict]:
        """
        Return all member devices of a virtual chassis.

        The master device (as recorded in the virtual chassis ``master``
        field) is placed first.  Remaining members are sorted by
        ``vc_position``.

        Parameters
        ----------
        vc_id : int
            NetBox virtual chassis primary key.

        Returns
        -------
        list[dict]
            Member device records — master first.

        Raises
        ------
        NetBoxClientError
            On API failure.
        """
        self.log.debug("get_virtual_chassis_members vc_id=%s", vc_id)
        try:
            records = list(self.nb.dcim.devices.filter(virtual_chassis_id=vc_id))
            members = [self._to_dict(r) for r in records]
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"VC member lookup failed for vc_id={vc_id}: {exc}"
            ) from exc

        # Identify master device ID from the VC record so it sorts first.
        master_id: Optional[int] = None
        try:
            vc_rec = self.nb.dcim.virtual_chassis.get(vc_id)
            if vc_rec:
                master = self._to_dict(vc_rec).get("master")
                master_id = (
                    master.get("id") if isinstance(master, dict) else master
                )
        except Exception:
            pass

        members.sort(
            key=lambda d: (
                0 if d.get("id") == master_id else 1,
                d.get("vc_position") or 99,
            )
        )
        return members

    def get_device_mgmt_ip(self, device: dict) -> Optional[str]:
        """
        Return the best available management IP for a device dict.

        Priority: ``primary_ip4`` → ``primary_ip6`` → ``oob_ip``
        (out-of-band).  The IP address is returned without its prefix
        length.

        Parameters
        ----------
        device : dict
            A plain device dict from :meth:`get_device` or
            :meth:`get_virtual_chassis_members`.

        Returns
        -------
        str or None
        """
        for field in ("primary_ip4", "primary_ip6", "oob_ip"):
            ip_field = device.get(field)
            if not ip_field:
                continue
            addr = (
                ip_field.get("address", "")
                if isinstance(ip_field, dict)
                else str(ip_field)
            )
            if addr:
                return addr.split("/")[0]
        return None

    # ----------------------------------------------------------------------- #
    # Device create / update                                                   #
    # ----------------------------------------------------------------------- #

    def create_device(self, device_payload: dict) -> dict:
        """
        Create a new device in NetBox.

        Parameters
        ----------
        device_payload : dict
            Required fields:

            - ``name``        – device hostname
            - ``device_type`` – NetBox device-type ID (integer)
            - ``role``        – NetBox device-role ID (integer)
            - ``site``        – NetBox site ID (integer)

            Any additional fields are forwarded to the API as-is.

        Returns
        -------
        dict
            The newly created device record.

        Raises
        ------
        NetBoxClientError
            On missing required fields or API failure.
        """
        self._validate_payload(
            device_payload,
            required=["name", "device_type", "role", "site"],
            context="create_device",
        )
        self.log.debug("create_device name=%r", device_payload.get("name"))
        try:
            rec = self.nb.dcim.devices.create(device_payload)
            return self._to_dict(rec)
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(f"create_device failed: {exc}") from exc

    def update_device(self, device_id: int, device_payload: dict) -> dict:
        """
        Update fields on an existing device (partial update supported).

        Parameters
        ----------
        device_id : int
            NetBox primary key of the device to update.
        device_payload : dict
            Fields to update.  Only provided keys are changed.

        Returns
        -------
        dict
            The updated device record.

        Raises
        ------
        NetBoxClientError
            If the device is not found or the API call fails.
        """
        self.log.debug("update_device id=%s payload_keys=%s", device_id, list(device_payload))
        rec = self._require_device(device_id=device_id, _raw=True)
        try:
            rec.update(device_payload)
            return self._to_dict(rec)
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"update_device(id={device_id}) failed: {exc}"
            ) from exc

    # ----------------------------------------------------------------------- #
    # Interface methods                                                        #
    # ----------------------------------------------------------------------- #

    def create_interface(self, interface_payload: dict) -> dict:
        """
        Create a new interface in NetBox.

        Parameters
        ----------
        interface_payload : dict
            Required fields:

            - ``device`` – parent device ID (integer)
            - ``name``   – interface name (e.g. ``"GigabitEthernet0/0/1"``)
            - ``type``   – interface type slug (e.g. ``"1000base-t"``)

            Any additional fields are forwarded to the API as-is.

        Returns
        -------
        dict
            The newly created interface record.

        Raises
        ------
        NetBoxClientError
            On missing required fields or API failure.
        """
        self._validate_payload(
            interface_payload,
            required=["device", "name", "type"],
            context="create_interface",
        )
        self.log.debug(
            "create_interface device=%s name=%r",
            interface_payload.get("device"),
            interface_payload.get("name"),
        )
        try:
            rec = self.nb.dcim.interfaces.create(interface_payload)
            return self._to_dict(rec)
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(f"create_interface failed: {exc}") from exc

    def update_interface(
        self,
        interface_id: int,
        interface_payload: dict,
    ) -> dict:
        """
        Update fields on an existing interface (partial update supported).

        Parameters
        ----------
        interface_id : int
            NetBox primary key of the interface to update.
        interface_payload : dict
            Fields to update.  Only provided keys are changed.

        Returns
        -------
        dict
            The updated interface record.

        Raises
        ------
        NetBoxClientError
            If the interface is not found or the API call fails.
        """
        self.log.debug(
            "update_interface id=%s payload_keys=%s",
            interface_id, list(interface_payload),
        )
        try:
            rec = self.nb.dcim.interfaces.get(interface_id)
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"update_interface: lookup for id={interface_id} failed: {exc}"
            ) from exc

        if rec is None:
            raise NetBoxClientError(
                f"update_interface: interface id={interface_id} not found."
            )
        try:
            rec.update(interface_payload)
            return self._to_dict(rec)
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"update_interface(id={interface_id}) failed: {exc}"
            ) from exc

    def find_interface_by_name_vc(
        self,
        device_ids: List[int],
        name: str,
    ) -> Optional[dict]:
        """
        Search for an interface by *name* across all device IDs in *device_ids*.

        Returns the first matching interface dict (with all fields from
        ``_to_dict``), or ``None`` when the interface is not found on any
        of the listed devices.  Useful for detecting mis-placed interfaces
        across Virtual Chassis members before relocating them.

        Parameters
        ----------
        device_ids : list[int]
            NetBox device primary keys to search, in order.
        name : str
            Exact interface name (e.g. ``"TwentyFiveGigE2/1/0/28"``).

        Returns
        -------
        dict or None
        """
        for dev_id in device_ids:
            self.log.debug(
                "find_interface_by_name_vc dev_id=%s name=%r", dev_id, name
            )
            try:
                recs = list(
                    self.nb.dcim.interfaces.filter(device_id=dev_id, name=name)
                )
            except pynetbox.RequestError as exc:
                self.log.debug(
                    "find_interface_by_name_vc: lookup failed dev_id=%s name=%r: %s",
                    dev_id, name, exc,
                )
                continue
            if recs:
                return self._to_dict(recs[0])
        return None

    def list_interface_ips(self, interface_id: int) -> List[dict]:
        """
        Return all IP address records currently assigned to *interface_id*.

        Parameters
        ----------
        interface_id : int
            NetBox interface primary key.

        Returns
        -------
        list[dict]
            Zero or more IP address records.

        Raises
        ------
        NetBoxClientError
            On API failure.
        """
        self.log.debug("list_interface_ips interface_id=%s", interface_id)
        try:
            recs = list(
                self.nb.ipam.ip_addresses.filter(interface_id=interface_id)
            )
            return [self._to_dict(r) for r in recs]
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"list_interface_ips(id={interface_id}) failed: {exc}"
            ) from exc

    def delete_interface(self, interface_id: int) -> None:
        """
        Delete a NetBox interface by primary key.

        Raises
        ------
        NetBoxClientError
            On API failure, including dependency conflicts (e.g. a cable is
            attached — caller should catch and skip relocation in that case).
        """
        self.log.debug("delete_interface id=%s", interface_id)
        try:
            rec = self.nb.dcim.interfaces.get(interface_id)
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"delete_interface: lookup for id={interface_id} failed: {exc}"
            ) from exc

        if rec is None:
            self.log.debug("delete_interface: id=%s already absent", interface_id)
            return

        try:
            ok = rec.delete()
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"delete_interface(id={interface_id}) failed: {exc}"
            ) from exc

        if not ok:
            raise NetBoxClientError(
                f"delete_interface(id={interface_id}): API returned false"
            )

    # ----------------------------------------------------------------------- #
    # Module bay + installed module methods                                    #
    # ----------------------------------------------------------------------- #

    def build_device_module_map(self, device_id: int) -> Dict[int, int]:
        """
        Return ``{slot_number: module_id}`` for all installed modules on a device.

        Slot numbers are extracted from module-bay name/label using a
        tolerant numeric search: ``"Slot 1"``, ``"LC-1"``, ``"Bay1"``,
        ``"1"``, etc.  When multiple numeric tokens appear in a label the
        last one is used (e.g. ``"LC-Slot-1"`` → 1).

        Module bays that have no installed module are skipped.  When two
        bays resolve to the same slot number the first one is kept and a
        debug message is emitted.

        Parameters
        ----------
        device_id : int
            NetBox device primary key.

        Returns
        -------
        dict
            ``{slot_int: module_id_int}``; empty when no modules are
            installed or the device has no module bays.

        Raises
        ------
        NetBoxClientError
            On API failure.
        """
        self.log.debug("build_device_module_map device_id=%s", device_id)
        mapping: Dict[int, int] = {}

        try:
            bays = list(self.nb.dcim.module_bays.filter(device_id=device_id))
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"build_device_module_map: bay lookup failed for "
                f"device_id={device_id}: {exc}"
            ) from exc

        for bay in bays:
            bay_dict = self._to_dict(bay)
            bay_id   = bay_dict.get("id")
            label    = bay_dict.get("name") or bay_dict.get("label") or ""
            slot_num = self._extract_slot_number(label)
            if slot_num is None:
                self.log.debug(
                    "build_device_module_map: bay_id=%s label=%r — "
                    "no numeric slot token; skipped", bay_id, label,
                )
                continue

            try:
                mods = list(self.nb.dcim.modules.filter(module_bay_id=bay_id))
            except pynetbox.RequestError as exc:
                self.log.debug(
                    "build_device_module_map: module lookup for bay_id=%s: %s",
                    bay_id, exc,
                )
                continue

            if not mods:
                continue

            mod_id = int(mods[0].id)
            if slot_num in mapping:
                self.log.debug(
                    "build_device_module_map: duplicate slot_num=%s for "
                    "device_id=%s — keeping first match", slot_num, device_id,
                )
            else:
                mapping[slot_num] = mod_id

        self.log.debug(
            "build_device_module_map device_id=%s → %d slot(s): %s",
            device_id, len(mapping), mapping,
        )
        return mapping

    @staticmethod
    def _extract_slot_number(label: str) -> Optional[int]:
        """
        Extract the last numeric token from a module-bay name/label.

        Returns ``None`` when no digit sequence is found.
        """
        tokens = re.findall(r"\d+", label or "")
        return int(tokens[-1]) if tokens else None

    # ----------------------------------------------------------------------- #
    # Helper / private methods                                                 #
    # ----------------------------------------------------------------------- #

    def _to_dict(self, record: Any) -> Optional[dict]:
        """
        Convert a pynetbox Record to a plain dict.

        pynetbox Records behave like dicts when passed to ``dict()``, and
        nested Records (e.g. ``device_type``, ``site``) are also converted
        to their dict representations by the same call.

        Parameters
        ----------
        record : pynetbox.Record or None

        Returns
        -------
        dict or None
        """
        if record is None:
            return None
        return dict(record)

    def _require_device(
        self,
        device_name: Optional[str] = None,
        device_id: Optional[int] = None,
        _raw: bool = False,
    ) -> Any:
        """
        Return a device record or raise ``NetBoxClientError`` if not found.

        Parameters
        ----------
        device_name : str, optional
        device_id : int, optional
        _raw : bool
            Internal flag.  When ``True``, return the raw pynetbox Record
            instead of a dict (needed for in-place ``.update()`` calls).

        Returns
        -------
        dict or pynetbox.Record

        Raises
        ------
        NetBoxClientError
            If neither identifier is provided, if the lookup fails, or if
            the device does not exist.
        """
        try:
            if device_id is not None:
                rec = self.nb.dcim.devices.get(device_id)
            elif device_name is not None:
                rec = self.nb.dcim.devices.get(name=device_name)
            else:
                raise NetBoxClientError(
                    "_require_device: either device_name or device_id must be provided."
                )
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(f"Device lookup failed: {exc}") from exc

        if rec is None:
            identifier = (
                device_id if device_id is not None else repr(device_name)
            )
            raise NetBoxClientError(
                f"Device {identifier} not found in NetBox."
            )
        return rec if _raw else self._to_dict(rec)

    @staticmethod
    def _validate_payload(
        payload: dict,
        required: List[str],
        context: str,
    ) -> None:
        """
        Raise ``NetBoxClientError`` if any required keys are absent from *payload*.

        Parameters
        ----------
        payload : dict
            The dict to validate.
        required : list[str]
            Keys that must be present.
        context : str
            Method name included in the error message for clarity.
        """
        missing = [k for k in required if k not in payload]
        if missing:
            raise NetBoxClientError(
                f"{context}: missing required field(s) {missing}. "
                f"Provided keys: {list(payload.keys())}"
            )

    def upsert_interface(
        self,
        device_id: int,
        name: str,
        payload: dict,
    ) -> dict:
        """
        Idempotently create or update a NetBox interface.

        Lookup is by ``(device_id, name)``.  When the interface already
        exists, the method compares existing field values to *payload* and
        issues a PATCH only when there are actual changes.  When it does
        not exist, a new interface is created with ``type="other"`` as
        the default (override by including ``"type"`` in *payload*).

        ``None`` values in *payload* are silently skipped, so callers may
        pass the full inventory dict without worrying about unsupported
        fields or missing data.

        Parameters
        ----------
        device_id : int
            NetBox device primary key.
        name : str
            Interface name, exact match (e.g. ``"GigabitEthernet0/0/1"``).
        payload : dict
            Fields to set.  Common keys: ``description``, ``speed``
            (kbps int), ``duplex`` (``"full"``|``"half"``|``"auto"``).

        Returns
        -------
        dict::

            {
                "id":      int,
                "name":    str,
                "action":  "created" | "updated" | "skipped",
                "changes": dict,   # populated for "updated"; empty otherwise
                "record":  dict,   # full NetBox interface record
            }

        Raises
        ------
        NetBoxClientError
            On any API failure.
        """
        # Drop None values — the device may not have reported certain fields.
        clean = {k: v for k, v in payload.items() if v is not None}

        self.log.debug("upsert_interface device_id=%s name=%r", device_id, name)
        try:
            existing_records = list(
                self.nb.dcim.interfaces.filter(device_id=device_id, name=name)
            )
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"upsert_interface: lookup failed for device_id={device_id} "
                f"name={name!r}: {exc}"
            ) from exc

        if not existing_records:
            # Build the minimal create payload then merge optional fields.
            create_payload: dict = {
                "device": device_id,
                "name":   name,
                "type":   clean.pop("type", "other"),
            }
            create_payload.update(clean)

            self.log.debug(
                "upsert_interface: creating %r on device %s", name, device_id
            )
            try:
                rec = self.nb.dcim.interfaces.create(create_payload)
            except pynetbox.RequestError as exc:
                raise NetBoxClientError(
                    f"upsert_interface: create failed for {name!r} on "
                    f"device_id={device_id}: {exc}"
                ) from exc
            return {
                "id":      rec.id,
                "name":    name,
                "action":  "created",
                "changes": create_payload,
                "record":  self._to_dict(rec),
            }

        # Interface exists — detect changes.
        rec = existing_records[0]
        rec_dict = self._to_dict(rec)

        changes = self._diff_interface_fields(rec_dict, clean)
        if not changes:
            self.log.debug(
                "upsert_interface: no changes for %r on device %s — skipped",
                name, device_id,
            )
            return {
                "id":      rec.id,
                "name":    name,
                "action":  "skipped",
                "changes": {},
                "record":  rec_dict,
            }

        self.log.debug(
            "upsert_interface: updating %r on device %s changes=%s",
            name, device_id, list(changes),
        )
        try:
            rec.update(changes)
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"upsert_interface: update failed for {name!r} on "
                f"device_id={device_id}: {exc}"
            ) from exc
        return {
            "id":      rec.id,
            "name":    name,
            "action":  "updated",
            "changes": changes,
            "record":  self._to_dict(rec),
        }

    # ----------------------------------------------------------------------- #
    # Site + VLAN group methods                                                #
    # ----------------------------------------------------------------------- #

    def get_site_for_device(self, device_id: int) -> dict:
        """
        Return the site dict for a device.

        Parameters
        ----------
        device_id : int
            NetBox device primary key.

        Returns
        -------
        dict
            The site record.

        Raises
        ------
        NetBoxClientError
            If the device is not found or has no site assigned.
        """
        device = self._require_device(device_id=device_id)
        site = device.get("site")
        if not site:
            raise NetBoxClientError(
                f"Device id={device_id} has no site assigned in NetBox."
            )
        if isinstance(site, dict) and "id" in site:
            return site
        # site is a bare ID — fetch the full record
        try:
            rec = self.nb.dcim.sites.get(int(site))
            return self._to_dict(rec) if rec else {"id": int(site)}
        except Exception as exc:
            raise NetBoxClientError(
                f"Could not fetch site for device id={device_id}: {exc}"
            ) from exc

    def find_vlan_group_for_site(
        self,
        site_id: int,
        deny_substring: str = "internet",
    ) -> dict:
        """
        Find a VLAN group scoped to *site_id*.

        Selection rules
        ---------------
        - Must be scoped to the given site.  Three strategies are tried in
          order so the method works across all NetBox versions:

          1. ``scope_type="dcim.site" & scope_id=<id>``  (NetBox 3.5+)
          2. ``site_id=<id>``                             (legacy field)
          3. Fetch all groups and match in Python          (last resort)

        - Groups whose name contains *deny_substring* (case-insensitive)
          are excluded.
        - Returns the first remaining group.

        Raises
        ------
        NetBoxClientError
            ``"Missing VLAN group for site: <site-name>"`` when no valid
            group is found.
        """
        self.log.debug("find_vlan_group_for_site site_id=%s", site_id)
        site_groups: List[dict] = []

        # ── Strategy 1: scope filter (NetBox 3.5 / 4.x) ──────────────────
        try:
            records = list(self.nb.ipam.vlan_groups.filter(
                scope_type="dcim.site", scope_id=site_id,
            ))
            site_groups = [self._to_dict(r) for r in records]
            self.log.debug(
                "find_vlan_group_for_site: scope filter → %d group(s)", len(site_groups)
            )
        except Exception as exc:
            self.log.debug("VLAN group scope filter error: %s", exc)

        # ── Strategy 2: legacy site field ─────────────────────────────────
        if not site_groups:
            try:
                records = list(self.nb.ipam.vlan_groups.filter(site_id=site_id))
                site_groups = [self._to_dict(r) for r in records]
                self.log.debug(
                    "find_vlan_group_for_site: site filter → %d group(s)", len(site_groups)
                )
            except Exception as exc:
                self.log.debug("VLAN group site filter error: %s", exc)

        # ── Strategy 3: full scan + Python match (fallback) ───────────────
        if not site_groups:
            self.log.debug("find_vlan_group_for_site: falling back to full scan")
            try:
                all_groups = list(self.nb.ipam.vlan_groups.all())
                for g in all_groups:
                    try:
                        g_dict = self._to_dict(g)
                        if self._vlan_group_matches_site(g_dict, site_id):
                            site_groups.append(g_dict)
                    except Exception as inner:
                        self.log.debug("VLAN group match error for %r: %s", g, inner)
            except Exception as exc:
                raise NetBoxClientError(
                    f"Failed to fetch VLAN groups: {exc}"
                ) from exc

        if not site_groups:
            site_name = self._get_site_name(site_id)
            raise NetBoxClientError(f"Missing VLAN group for site: {site_name}")

        deny_lower = deny_substring.lower()
        valid = [
            g for g in site_groups
            if deny_lower not in (g.get("name") or "").lower()
        ]
        if not valid:
            site_name = self._get_site_name(site_id)
            raise NetBoxClientError(
                f"Missing VLAN group for site: {site_name} "
                f"(all found groups contain {deny_substring!r} in name)"
            )

        return valid[0]

    def ensure_vlan_in_site_group(
        self,
        site_id: int,
        vlan_group_id: int,
        vid: int,
        name: Optional[str] = None,
    ) -> dict:
        """
        Ensure a VLAN exists in the specified VLAN group.

        Creates the VLAN if it is absent; returns the existing record
        otherwise.  The returned dict includes ``"_action": "created"``
        or ``"_action": "existing"``.

        Parameters
        ----------
        site_id : int
            NetBox site ID (used when creating the VLAN).
        vlan_group_id : int
            NetBox VLAN group ID.
        vid : int
            VLAN ID (802.1Q).
        name : str, optional
            VLAN name; defaults to ``"VLAN{vid:04d}"`` when omitted.

        Returns
        -------
        dict
        """
        self.log.debug(
            "ensure_vlan_in_site_group vid=%s group_id=%s", vid, vlan_group_id
        )
        try:
            existing = list(
                self.nb.ipam.vlans.filter(vid=vid, group_id=vlan_group_id)
            )
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"VLAN lookup failed vid={vid} group={vlan_group_id}: {exc}"
            ) from exc

        if existing:
            d = self._to_dict(existing[0])
            d["_action"] = "existing"
            return d

        # Resolve the candidate name, then check for collisions within the
        # same VLAN group.  NetBox enforces unique names inside a group, so if
        # another VID already holds the same name we append "_{vid}" to avoid
        # a 400 rejection.
        # Example: VLAN 2 named "voice" → "voice_2" when "voice" is taken.
        candidate_name = name or f"VLAN{vid:04d}"
        final_name     = candidate_name

        try:
            name_collisions = [
                v for v in self.nb.ipam.vlans.filter(
                    name=candidate_name, group_id=vlan_group_id
                )
                if int(getattr(v, "vid", 0)) != vid
            ]
        except pynetbox.RequestError as exc:
            # Non-fatal — proceed with the original name and let the create
            # surface any actual conflict.
            self.log.debug(
                "ensure_vlan_in_site_group: name-collision check failed "
                "vid=%s name=%r: %s — proceeding with original name",
                vid, candidate_name, exc,
            )
            name_collisions = []

        if name_collisions:
            final_name = f"{candidate_name}_{vid}"
            self.log.info(
                "ensure_vlan_in_site_group: name %r already used in group %s "
                "by VID %s — using %r for VID %s",
                candidate_name, vlan_group_id,
                getattr(name_collisions[0], "vid", "?"),
                final_name, vid,
            )

        payload: dict = {
            "vid":    vid,
            "name":   final_name,
            "group":  vlan_group_id,
            "site":   site_id,
            "status": "active",
        }
        self.log.debug(
            "ensure_vlan_in_site_group: creating VLAN %s name=%r", vid, final_name
        )
        try:
            rec = self.nb.ipam.vlans.create(payload)
            d = self._to_dict(rec)
            d["_action"] = "created"
            return d
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"VLAN create failed vid={vid} group={vlan_group_id}: {exc}"
            ) from exc

    def ensure_vlan_site_consistency(
        self,
        vlan_id: int,
        site_id: int,
    ) -> dict:
        """
        Ensure a VLAN is assigned to the correct site.

        VLANs in NetBox use the legacy ``site`` field (not ``scope``).
        When the VLAN's current site does not match *site_id* the record
        is updated and ``"_action": "updated"`` is returned.  If the site
        already matches, ``"_action": "skipped"`` is returned without any
        API write.

        Parameters
        ----------
        vlan_id : int
            NetBox VLAN primary key.
        site_id : int
            The site the VLAN must belong to.

        Returns
        -------
        dict
            VLAN record with ``"_action": "created"|"updated"|"skipped"``.

        Raises
        ------
        NetBoxClientError
            If the VLAN is not found or the update fails.
        """
        self.log.debug(
            "ensure_vlan_site_consistency vlan_id=%s site_id=%s",
            vlan_id, site_id,
        )
        try:
            rec = self.nb.ipam.vlans.get(vlan_id)
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"ensure_vlan_site_consistency: lookup failed for "
                f"vlan_id={vlan_id}: {exc}"
            ) from exc

        if rec is None:
            raise NetBoxClientError(
                f"ensure_vlan_site_consistency: VLAN id={vlan_id} not found."
            )

        rec_dict = self._to_dict(rec)
        cur_site_id = self._extract_nested_id(rec_dict.get("site"))

        if cur_site_id == site_id:
            rec_dict["_action"] = "skipped"
            return rec_dict

        site_name = self._get_site_name(site_id)
        self.log.info(
            "Moved VLAN id=%s to site %r", vlan_id, site_name
        )
        try:
            rec.update({"site": site_id})
            d = self._to_dict(rec)
            d["_action"] = "updated"
            return d
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"ensure_vlan_site_consistency: update failed for "
                f"vlan_id={vlan_id}: {exc}"
            ) from exc

    # ----------------------------------------------------------------------- #
    # VRF methods                                                              #
    # ----------------------------------------------------------------------- #

    def get_vrf_by_name(self, name: str) -> Optional[dict]:
        """
        Return the first NetBox VRF whose name matches *name* exactly,
        or ``None`` when not found.

        The lookup is case-sensitive (NetBox VRF names are case-sensitive).

        Parameters
        ----------
        name : str
            VRF name, e.g. ``"CORP"`` or ``"MGMT"``.

        Returns
        -------
        dict or None

        Raises
        ------
        NetBoxClientError
            On API failure.
        """
        self.log.debug("get_vrf_by_name name=%r", name)
        try:
            recs = list(self.nb.ipam.vrfs.filter(name=name))
            return self._to_dict(recs[0]) if recs else None
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"get_vrf_by_name({name!r}) failed: {exc}"
            ) from exc

    def create_vrf(
        self,
        name: str,
        enforce_unique: bool = False,
    ) -> dict:
        """
        Create a new VRF in NetBox.

        Parameters
        ----------
        name : str
            VRF name, e.g. ``"CORP"``.
        enforce_unique : bool
            Whether NetBox should prevent duplicate IP addresses within this
            VRF (default ``False`` — flexible for automated environments).

        Returns
        -------
        dict
            The newly created VRF record.

        Raises
        ------
        NetBoxClientError
            On API failure.
        """
        self.log.debug("create_vrf name=%r enforce_unique=%s", name, enforce_unique)
        payload: dict = {
            "name":           name,
            "enforce_unique": enforce_unique,
        }
        try:
            rec = self.nb.ipam.vrfs.create(payload)
            return self._to_dict(rec)
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"create_vrf({name!r}) failed: {exc}"
            ) from exc

    def ensure_vrf(
        self,
        name: str,
        enforce_unique: bool = False,
    ) -> dict:
        """
        Idempotently ensure a VRF named *name* exists in NetBox.

        Returns the existing record when already present
        (``"_action": "existing"``), or the newly created record
        (``"_action": "created"``).

        Parameters
        ----------
        name : str
            VRF name (case-sensitive).
        enforce_unique : bool
            Passed to :meth:`create_vrf` when the VRF is absent.

        Returns
        -------
        dict
            VRF record with ``"_action": "existing"|"created"``.

        Raises
        ------
        NetBoxClientError
            On API failure.
        """
        self.log.debug("ensure_vrf name=%r", name)
        existing = self.get_vrf_by_name(name)
        if existing:
            existing["_action"] = "existing"
            self.log.debug("ensure_vrf: %r already exists id=%s", name, existing["id"])
            return existing

        self.log.info("ensure_vrf: VRF %r not found in NetBox — creating", name)
        rec = self.create_vrf(name, enforce_unique=enforce_unique)
        rec["_action"] = "created"
        self.log.info("ensure_vrf: VRF %r created id=%s", name, rec["id"])
        return rec

    # ----------------------------------------------------------------------- #
    # Prefix methods                                                           #
    # ----------------------------------------------------------------------- #

    def ensure_prefix(
        self,
        prefix_cidr: str,
        site_id: int,
        vlan_id: Optional[int] = None,
        vrf_id: Optional[int] = None,
    ) -> dict:
        """
        Ensure a prefix exists in NetBox, assigned to the correct site and VRF.

        Behaviour
        ---------
        - **Not found** (matching CIDR *and* VRF): create with site scope,
          optional VLAN, and optional VRF.
        - **Found, all fields match**: return as-is (``_action="existing"``).
        - **Found, wrong site**: update site scope (``_action="moved_site"``).
        - **Found, VLAN or VRF differs**: update those fields
          (``_action="updated"``).

        When *vrf_id* is supplied the lookup is scoped to that VRF so the
        same CIDR can coexist under multiple VRFs without conflict.

        Parameters
        ----------
        prefix_cidr : str
            CIDR prefix string, e.g. ``"10.1.2.0/24"``.
        site_id : int
            NetBox site ID to assign.
        vlan_id : int, optional
            NetBox VLAN ID to link to the prefix.
        vrf_id : int, optional
            NetBox VRF primary key.  ``None`` means the global routing table.

        Returns
        -------
        dict
            Prefix record plus ``"_action"`` metadata key.
        """
        self.log.debug(
            "ensure_prefix %s site_id=%s vlan_id=%s vrf_id=%s",
            prefix_cidr, site_id, vlan_id, vrf_id,
        )

        # Scope the lookup to the correct VRF so the same CIDR under different
        # VRFs is treated as a distinct prefix.
        try:
            filter_kwargs: dict = {"prefix": prefix_cidr}
            if vrf_id is not None:
                filter_kwargs["vrf_id"] = vrf_id
            else:
                filter_kwargs["vrf"] = "null"   # global table
            existing = list(self.nb.ipam.prefixes.filter(**filter_kwargs))
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"Prefix lookup failed {prefix_cidr!r}: {exc}"
            ) from exc

        if not existing:
            payload = self._build_prefix_payload(prefix_cidr, site_id, vlan_id, vrf_id)
            self.log.debug("ensure_prefix: creating %s vrf_id=%s", prefix_cidr, vrf_id)
            try:
                rec = self.nb.ipam.prefixes.create(payload)
                d = self._to_dict(rec)
                d["_action"] = "created"
                return d
            except pynetbox.RequestError as exc:
                raise NetBoxClientError(
                    f"Prefix create failed {prefix_cidr!r}: {exc}"
                ) from exc

        rec = existing[0]
        rec_dict = self._to_dict(rec)
        changes = self._diff_prefix_site_vlan(rec_dict, site_id, vlan_id, vrf_id)
        if not changes:
            rec_dict["_action"] = "existing"
            return rec_dict

        action = "moved_site" if any(
            k in changes for k in ("site", "scope_type", "scope_id")
        ) else "updated"
        self.log.debug(
            "ensure_prefix: updating %s changes=%s", prefix_cidr, list(changes)
        )
        try:
            rec.update(changes)
            d = self._to_dict(rec)
            d["_action"] = action
            return d
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"Prefix update failed {prefix_cidr!r}: {exc}"
            ) from exc

    # ----------------------------------------------------------------------- #
    # Interface VLAN methods                                                   #
    # ----------------------------------------------------------------------- #

    def ensure_svi_interface(
        self,
        device_id: int,
        interface_name: str,
        vlan_id: int,
    ) -> dict:
        """
        Ensure a virtual (SVI) interface exists in NetBox and is linked to
        its VLAN.

        The interface is written with:
        - ``type = "virtual"``  — the NetBox SVI interface type
        - ``mode = "access"``   — enables the ``untagged_vlan`` field
        - ``untagged_vlan = vlan_id``

        Idempotent: no change is made when the interface already has the
        correct mode and VLAN assignment.

        Parameters
        ----------
        device_id : int
            NetBox device primary key.
        interface_name : str
            SVI name as it appears on the device, e.g. ``"Vlan162"``.
        vlan_id : int
            NetBox VLAN primary key to link.

        Returns
        -------
        dict
            Interface record with ``"_action": "created"|"updated"|"skipped"``.
        """
        self.log.info(
            "ensure_svi_interface %r device_id=%s vlan_id=%s",
            interface_name, device_id, vlan_id,
        )
        try:
            existing = list(
                self.nb.dcim.interfaces.filter(
                    device_id=device_id, name=interface_name,
                )
            )
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"ensure_svi_interface: lookup failed for {interface_name!r}: {exc}"
            ) from exc

        if not existing:
            payload: dict = {
                "device":        device_id,
                "name":          interface_name,
                "type":          "virtual",
                "mode":          "access",
                "untagged_vlan": vlan_id,
            }
            self.log.debug(
                "ensure_svi_interface: creating %r vlan_id=%s",
                interface_name, vlan_id,
            )
            try:
                rec = self.nb.dcim.interfaces.create(payload)
                d = self._to_dict(rec)
                d["_action"] = "created"
                return d
            except pynetbox.RequestError as exc:
                raise NetBoxClientError(
                    f"ensure_svi_interface: create failed for "
                    f"{interface_name!r}: {exc}"
                ) from exc

        # Interface exists — check what needs correcting.
        rec = existing[0]
        rec_dict = self._to_dict(rec)
        changes: dict = {}

        cur_mode = rec_dict.get("mode") or {}
        if isinstance(cur_mode, dict):
            cur_mode = cur_mode.get("value", "")
        if cur_mode != "access":
            changes["mode"] = "access"

        cur_uv_id = self._extract_nested_id(rec_dict.get("untagged_vlan"))
        if cur_uv_id != vlan_id:
            changes["untagged_vlan"] = vlan_id

        if not changes:
            self.log.debug(
                "ensure_svi_interface: %r already linked to vlan_id=%s — skipped",
                interface_name, vlan_id,
            )
            rec_dict["_action"] = "skipped"
            return rec_dict

        self.log.debug(
            "ensure_svi_interface: updating %r changes=%s",
            interface_name, list(changes),
        )
        try:
            rec.update(changes)
            d = self._to_dict(rec)
            d["_action"] = "updated"
            return d
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"ensure_svi_interface: update failed for "
                f"{interface_name!r}: {exc}"
            ) from exc

    def upsert_interface_vlans(
        self,
        device_id: int,
        interface_name: str,
        mode: str,
        native_vlan_id: Optional[int],
        tagged_vlan_ids: List[int],
    ) -> dict:
        """
        Idempotently set 802.1Q mode, untagged VLAN, and tagged VLANs on an
        interface.

        Parameters
        ----------
        device_id : int
            NetBox device primary key.
        interface_name : str
            Exact interface name.
        mode : str
            ``"trunk"`` (→ ``"tagged"``), ``"access"`` (→ ``"access"``),
            or ``"tagged-all"`` (→ ``"tagged-all"``).
        native_vlan_id : int or None
            NetBox VLAN ID for the native/untagged VLAN.
        tagged_vlan_ids : list[int]
            NetBox VLAN IDs for the tagged VLAN list.

        Returns
        -------
        dict
            Updated or unchanged interface record with ``"_action"`` key.

        Raises
        ------
        NetBoxClientError
            If the interface is not found or the API call fails.
        """
        self.log.debug(
            "upsert_interface_vlans device_id=%s iface=%r mode=%s",
            device_id, interface_name, mode,
        )
        try:
            existing = list(
                self.nb.dcim.interfaces.filter(
                    device_id=device_id, name=interface_name
                )
            )
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"Interface lookup failed {interface_name!r}: {exc}"
            ) from exc

        if not existing:
            raise NetBoxClientError(
                f"Interface {interface_name!r} not found on device_id={device_id}."
            )

        rec = existing[0]
        rec_dict = self._to_dict(rec)

        nb_mode = {"trunk": "tagged", "access": "access", "tagged-all": "tagged-all"}.get(
            mode.lower(), "tagged"
        )
        desired_tagged = sorted(set(tagged_vlan_ids))

        # Extract current values
        cur_mode = rec_dict.get("mode") or {}
        if isinstance(cur_mode, dict):
            cur_mode = cur_mode.get("value", "")

        cur_native = rec_dict.get("untagged_vlan")
        cur_native_id = cur_native.get("id") if isinstance(cur_native, dict) else cur_native

        cur_tagged = rec_dict.get("tagged_vlans") or []
        cur_tagged_ids = sorted(set(
            t.get("id") if isinstance(t, dict) else t for t in cur_tagged
        ))

        if (cur_mode == nb_mode
                and cur_native_id == native_vlan_id
                and cur_tagged_ids == desired_tagged):
            rec_dict["_action"] = "skipped"
            return rec_dict

        payload: dict = {
            "mode":          nb_mode,
            "untagged_vlan": native_vlan_id,
            "tagged_vlans":  desired_tagged,
        }
        try:
            rec.update(payload)
            d = self._to_dict(rec)
            d["_action"] = "updated"
            return d
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"Interface VLAN update failed {interface_name!r}: {exc}"
            ) from exc

    # ----------------------------------------------------------------------- #
    # NetBox version + scope compatibility helpers                             #
    # ----------------------------------------------------------------------- #

    def _get_nb_version(self) -> Tuple[int, int]:
        """
        Return the NetBox ``(major, minor)`` version tuple.

        Result is cached after the first call.  Returns ``(0, 0)`` if the
        version cannot be determined.
        """
        if hasattr(self, "_nb_version_cache"):
            return self._nb_version_cache
        try:
            resp = self.nb.http_session.get(f"{self.base_url}/api/status/")
            data = resp.json()
            v = data.get("netbox-version", "0.0")
            parts = str(v).split(".")
            self._nb_version_cache = (int(parts[0]), int(parts[1]))
        except Exception as exc:
            self.log.debug("Could not determine NetBox version: %s", exc)
            self._nb_version_cache = (0, 0)
        return self._nb_version_cache

    def _nb_supports_scope(self) -> bool:
        """
        Return ``True`` when this NetBox instance uses ``scope`` instead of
        ``site`` on Prefix records (NetBox 4.2+).
        """
        major, minor = self._get_nb_version()
        return (major, minor) >= (4, 2)

    def _build_prefix_payload(
        self,
        prefix_cidr: str,
        site_id: int,
        vlan_id: Optional[int] = None,
        vrf_id: Optional[int] = None,
    ) -> dict:
        """Build a minimal prefix creation payload with correct site scoping."""
        payload: dict = {"prefix": prefix_cidr}
        if self._nb_supports_scope():
            payload["scope_type"] = "dcim.site"
            payload["scope_id"]   = site_id
        else:
            payload["site"] = site_id
        if vlan_id is not None:
            payload["vlan"] = vlan_id
        if vrf_id is not None:
            payload["vrf"] = vrf_id
        return payload

    def _diff_prefix_site_vlan(
        self,
        existing: dict,
        site_id: int,
        vlan_id: Optional[int],
        vrf_id: Optional[int] = None,
    ) -> dict:
        """Return changes needed to align a prefix's site/scope, VLAN, and VRF."""
        changes: dict = {}

        current_site_id = self._extract_site_id_from_prefix(existing)
        if current_site_id != site_id:
            if self._nb_supports_scope():
                changes["scope_type"] = "dcim.site"
                changes["scope_id"]   = site_id
            else:
                changes["site"] = site_id

        if vlan_id is not None:
            # Use _extract_nested_id so plain dicts, pynetbox Records, and bare
            # integers are all handled correctly regardless of NetBox version.
            cur_vlan_id = self._extract_nested_id(existing.get("vlan"))
            if cur_vlan_id != vlan_id:
                changes["vlan"] = vlan_id
                self.log.debug(
                    "_diff_prefix_site_vlan: vlan %s → %s", cur_vlan_id, vlan_id
                )

        if vrf_id is not None:
            cur_vrf_id = self._extract_nested_id(existing.get("vrf"))
            if cur_vrf_id != vrf_id:
                changes["vrf"] = vrf_id
                self.log.debug(
                    "_diff_prefix_site_vlan: vrf %s → %s", cur_vrf_id, vrf_id
                )

        return changes

    def _extract_site_id_from_prefix(self, prefix_dict: dict) -> Optional[int]:
        """
        Extract the site ID from a prefix record dict.

        Handles both:
        - NetBox 4.2+ ``scope`` object (``scope_type`` = ``"dcim.site"``)
        - Legacy ``site`` field
        """
        scope = prefix_dict.get("scope")
        scope_type = prefix_dict.get("scope_type")
        if scope and scope_type:
            if "site" in str(scope_type).lower():
                return scope.get("id") if isinstance(scope, dict) else None
        site = prefix_dict.get("site")
        if site:
            return site.get("id") if isinstance(site, dict) else int(site)
        return None

    def find_vlan_id_by_vid(self, vid: int) -> Optional[int]:
        """
        Return the NetBox VLAN primary key for a given 802.1Q VID.

        Used as a fallback when the VID is not present in the local
        ``vlan_id_map`` — for example when a VLAN already existed in NetBox
        before this run but was not created by it.

        Parameters
        ----------
        vid : int
            802.1Q VLAN ID.

        Returns
        -------
        int or None
            The NetBox ``id`` of the first matching VLAN record, or ``None``
            when no match is found or the lookup fails.
        """
        self.log.debug("find_vlan_id_by_vid vid=%s", vid)
        try:
            recs = list(self.nb.ipam.vlans.filter(vid=vid))
            return int(recs[0].id) if recs else None
        except Exception as exc:
            self.log.debug("find_vlan_id_by_vid(%s) error: %s", vid, exc)
            return None

    def get_vlans_for_group(self, vlan_group_id: int) -> Dict[int, int]:
        """
        Return a ``{vid: netbox_vlan_id}`` map for **all** VLANs in a group.

        This is used to preload the complete VLAN map so that trunk
        interface VLAN assignments work even for VLANs that already existed
        in NetBox before this run.

        Parameters
        ----------
        vlan_group_id : int
            NetBox VLAN group primary key.

        Returns
        -------
        dict
            ``{802.1Q_vid: netbox_vlan_id}``
        """
        self.log.debug("get_vlans_for_group group_id=%s", vlan_group_id)
        try:
            records = list(self.nb.ipam.vlans.filter(group_id=vlan_group_id))
            return {int(r.vid): int(r.id) for r in records}
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"get_vlans_for_group({vlan_group_id}) failed: {exc}"
            ) from exc

    def _vlan_group_matches_site(self, g_dict: dict, site_id: int) -> bool:
        """
        Return ``True`` when *g_dict* is scoped to *site_id*.

        Handles both the modern ``scope`` / ``scope_type`` fields (NetBox
        3.5+) and the legacy ``site`` field, and is robust to pynetbox
        returning nested objects as either plain dicts or Record instances.
        """
        # ── Modern scope field ────────────────────────────────────────────
        scope      = g_dict.get("scope")
        scope_type = g_dict.get("scope_type")
        if scope and scope_type:
            # scope_type can be a string ("dcim.site") or a choice dict
            scope_type_str = (
                scope_type.get("value", "") if isinstance(scope_type, dict)
                else str(scope_type)
            )
            if "site" in scope_type_str.lower():
                s_id = self._extract_nested_id(scope)
                return s_id == site_id if s_id is not None else False

        # ── Legacy site field ─────────────────────────────────────────────
        site = g_dict.get("site")
        if site is not None:
            s_id = self._extract_nested_id(site)
            return s_id == site_id if s_id is not None else False

        return False

    @staticmethod
    def _extract_nested_id(obj: Any) -> Optional[int]:
        """
        Robustly extract an integer ID from a NetBox nested object.

        Handles: plain ``int``, plain ``dict``, pynetbox ``Record``
        (which exposes attributes but is not a ``dict`` subclass).

        Returns ``None`` when the ID cannot be determined.
        """
        if obj is None:
            return None
        if isinstance(obj, int):
            return obj
        # dict or dict-like (has .get)
        if hasattr(obj, "get"):
            val = obj.get("id")
            if val is not None:
                try:
                    return int(val)
                except (TypeError, ValueError):
                    pass
        # pynetbox Record: attribute access
        val = getattr(obj, "id", None)
        if val is not None:
            try:
                return int(val)
            except (TypeError, ValueError):
                pass
        return None

    def _get_site_name(self, site_id: int) -> str:
        """Return a site's name string, falling back to ``"id=<n>"``."""
        try:
            rec = self.nb.dcim.sites.get(site_id)
            if rec:
                return str(self._to_dict(rec).get("name", f"id={site_id}"))
        except Exception:
            pass
        return f"id={site_id}"

    def _diff_interface_fields(self, existing: dict, desired: dict) -> dict:
        """
        Return only fields in *desired* that differ from *existing*.

        NetBox returns choice fields (e.g. ``duplex``, ``type``) as nested
        dicts ``{"value": "full", "label": "Full duplex"}``.  This method
        unwraps the ``"value"`` for comparison so callers can pass plain
        scalar strings.

        Parameters
        ----------
        existing : dict
            Current NetBox record (plain dict from ``_to_dict``).
        desired : dict
            Desired field values — plain scalars.

        Returns
        -------
        dict
            Subset of *desired* containing only changed fields.
        """
        diff: dict = {}
        for key, new_val in desired.items():
            if new_val is None:
                continue
            old_val = existing.get(key)
            if isinstance(old_val, dict) and "value" in old_val:
                old_val = old_val["value"]
            if str(old_val) != str(new_val):
                diff[key] = new_val
        return diff

    # ----------------------------------------------------------------------- #
    # LAG / Port-channel interface management                                  #
    # ----------------------------------------------------------------------- #

    def ensure_lag_interface(self, device_id: int, lag_name: str) -> dict:
        """
        Ensure a LAG interface (``type=lag``) exists in NetBox.

        Parameters
        ----------
        device_id : int
        lag_name : str   e.g. ``"Port-channel10"``

        Returns
        -------
        dict
            Interface record with ``"_action": "created"|"existing"``.
        """
        self.log.debug("ensure_lag_interface device_id=%s name=%r", device_id, lag_name)
        try:
            existing = list(
                self.nb.dcim.interfaces.filter(device_id=device_id, name=lag_name)
            )
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"ensure_lag_interface: lookup failed for {lag_name!r}: {exc}"
            ) from exc

        if existing:
            d = self._to_dict(existing[0])
            d["_action"] = "existing"
            return d

        payload = {"device": device_id, "name": lag_name, "type": "lag"}
        self.log.debug("ensure_lag_interface: creating %r", lag_name)
        try:
            rec = self.nb.dcim.interfaces.create(payload)
            d = self._to_dict(rec)
            d["_action"] = "created"
            return d
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"ensure_lag_interface: create failed for {lag_name!r}: {exc}"
            ) from exc

    def set_interface_lag(
        self,
        device_id: int,
        interface_name: str,
        lag_interface_id: int,
    ) -> dict:
        """
        Assign a physical interface to a LAG by setting its ``lag`` field.

        Idempotent: no write if the interface is already attached to the
        correct LAG.

        Parameters
        ----------
        device_id : int
        interface_name : str
        lag_interface_id : int   NetBox primary key of the LAG interface.

        Returns
        -------
        dict
            Interface record with ``"_action": "updated"|"skipped"``.

        Raises
        ------
        NetBoxClientError
            If the interface is not found.
        """
        self.log.debug(
            "set_interface_lag device_id=%s iface=%r lag_id=%s",
            device_id, interface_name, lag_interface_id,
        )
        try:
            existing = list(
                self.nb.dcim.interfaces.filter(
                    device_id=device_id, name=interface_name
                )
            )
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"set_interface_lag: lookup failed for {interface_name!r}: {exc}"
            ) from exc

        if not existing:
            # Interface missing — create a minimal record then attach
            try:
                rec = self.nb.dcim.interfaces.create(
                    {"device": device_id, "name": interface_name, "type": "other"}
                )
            except pynetbox.RequestError as exc:
                raise NetBoxClientError(
                    f"set_interface_lag: could not create placeholder for "
                    f"{interface_name!r}: {exc}"
                ) from exc
            existing = [rec]

        rec = existing[0]
        rec_dict = self._to_dict(rec)

        cur_lag_id = self._extract_nested_id(rec_dict.get("lag"))
        if cur_lag_id == lag_interface_id:
            rec_dict["_action"] = "skipped"
            return rec_dict

        try:
            rec.update({"lag": lag_interface_id})
            d = self._to_dict(rec)
            d["_action"] = "updated"
            return d
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"set_interface_lag: update failed for {interface_name!r}: {exc}"
            ) from exc

    # ----------------------------------------------------------------------- #
    # Switchport / trunk VLAN (named alias exposed by spec)                    #
    # ----------------------------------------------------------------------- #

    def upsert_interface_switchport(
        self,
        device_id: int,
        interface_name: str,
        mode: str,
        native_vlan_id: Optional[int],
        tagged_vlan_ids: List[int],
    ) -> dict:
        """
        Idempotent trunk/access VLAN assignment on an interface.

        Maps cleanly to :meth:`upsert_interface_vlans`; exposed under the
        name required by Part 1-B of the specification.
        """
        return self.upsert_interface_vlans(
            device_id=device_id,
            interface_name=interface_name,
            mode=mode,
            native_vlan_id=native_vlan_id,
            tagged_vlan_ids=tagged_vlan_ids,
        )

    # ----------------------------------------------------------------------- #
    # Interface admin / oper state                                             #
    # ----------------------------------------------------------------------- #

    def update_interface_admin_oper(
        self,
        device_id: int,
        interface_name: str,
        enabled: bool,
        mark_connected: bool,
    ) -> dict:
        """
        Update ``enabled`` and ``mark_connected`` on an interface.

        Idempotent: skips the API write when both values already match.
        ``mark_connected`` is a NetBox 4.x field; when the API does not
        support it the field is silently omitted from the payload.

        Returns
        -------
        dict
            Interface record with ``"_action": "updated"|"skipped"``.
        """
        self.log.debug(
            "update_interface_admin_oper device_id=%s iface=%r enabled=%s connected=%s",
            device_id, interface_name, enabled, mark_connected,
        )
        try:
            existing = list(
                self.nb.dcim.interfaces.filter(
                    device_id=device_id, name=interface_name
                )
            )
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"update_interface_admin_oper: lookup failed for "
                f"{interface_name!r}: {exc}"
            ) from exc

        if not existing:
            # Interface not yet in NetBox — caller should create it first then
            # retry.  Return a distinct action so the caller can distinguish
            # this from "values already match" (which also returns "skipped").
            self.log.warning(
                "update_interface_admin_oper: %r not found on device_id=%s "
                "— will attempt to create",
                interface_name, device_id,
            )
            return {"_action": "not_found", "name": interface_name}

        rec = existing[0]
        rec_dict = self._to_dict(rec)
        changes: dict = {}

        if rec_dict.get("enabled") != enabled:
            changes["enabled"] = enabled

        # mark_connected is a NetBox 4.x field — but NetBox explicitly rejects
        # it on LAG interfaces ("Link Aggregation Group interfaces cannot be
        # marked as connected").  Skip it entirely for LAGs.
        cur_type = rec_dict.get("type") or {}
        if isinstance(cur_type, dict):
            cur_type = cur_type.get("value", "")
        is_lag = str(cur_type).lower() == "lag"

        # NetBox also rejects mark_connected=True on any interface that already
        # has a cable attached — cable and connected are mutually exclusive.
        # The `cable` field is non-None when a cable is present, so this
        # decision is made from the record already in hand (no extra API call).
        has_cable = rec_dict.get("cable") is not None
        if has_cable and mark_connected:
            self.log.info(
                "update_interface_admin_oper: skipping connected=True — "
                "cable exists on %r (device_id=%s)",
                interface_name, device_id,
            )
            mark_connected = False
        elif not has_cable and mark_connected:
            self.log.debug(
                "update_interface_admin_oper: setting connected=True on %r "
                "(no cable present, device_id=%s)",
                interface_name, device_id,
            )

        if (
            not is_lag
            and "mark_connected" in rec_dict
            and rec_dict["mark_connected"] != mark_connected
        ):
            changes["mark_connected"] = mark_connected

        if not changes:
            rec_dict["_action"] = "skipped"
            return rec_dict

        try:
            rec.update(changes)
            d = self._to_dict(rec)
            d["_action"] = "updated"
            return d
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"update_interface_admin_oper: update failed for "
                f"{interface_name!r}: {exc}"
            ) from exc

    def update_interface_state_cf(
        self,
        device_id: int,
        interface_name: str,
        state_value: str,
    ) -> dict:
        """
        Idempotently update the ``STATE`` custom field on a NetBox interface.

        Only the ``STATE`` key inside ``custom_fields`` is written; all other
        custom fields on the record are untouched (NetBox merges partial
        ``custom_fields`` dicts on PATCH).

        Parameters
        ----------
        device_id : int
            NetBox device primary key.
        interface_name : str
            Exact interface name as it appears in NetBox.
        state_value : str
            One of ``"UP"``, ``"DOWN"``, ``"ADMIN DOWN"``, or ``"UNKNOWN"``.

        Returns
        -------
        dict
            Interface record with ``"_action": "updated"|"skipped"``.

        Raises
        ------
        NetBoxClientError
            When the interface cannot be found or the API call fails.
        """
        self.log.debug(
            "update_interface_state_cf device_id=%s iface=%r state=%r",
            device_id, interface_name, state_value,
        )
        try:
            existing = list(
                self.nb.dcim.interfaces.filter(
                    device_id=device_id, name=interface_name
                )
            )
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"update_interface_state_cf: lookup failed for "
                f"{interface_name!r} on device_id={device_id}: {exc}"
            ) from exc

        if not existing:
            # Interface not yet in NetBox — graceful skip; will be created
            # on the next full sync run.
            self.log.debug(
                "update_interface_state_cf: %r not found on device_id=%s "
                "— skipped",
                interface_name, device_id,
            )
            return {"_action": "skipped", "name": interface_name}

        rec      = existing[0]
        rec_dict = self._to_dict(rec)
        cur_cf   = rec_dict.get("custom_fields") or {}
        cur_val  = str(cur_cf.get("STATE") or "")

        if cur_val == state_value:
            self.log.debug(
                "update_interface_state_cf: %r STATE already %r — skipped",
                interface_name, state_value,
            )
            rec_dict["_action"] = "skipped"
            return rec_dict

        try:
            rec.update({"custom_fields": {"STATE": state_value}})
            d = self._to_dict(rec)
            d["_action"] = "updated"
            return d
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"update_interface_state_cf: update failed for "
                f"{interface_name!r} payload={{'STATE': {state_value!r}}}: {exc}"
            ) from exc

    def get_interface_by_name(
        self,
        device_id: int,
        interface_name: str,
    ) -> Optional[dict]:
        """
        Return the first NetBox interface whose name matches *interface_name*
        on *device_id*, or ``None`` when not found.

        Parameters
        ----------
        device_id : int
        interface_name : str

        Returns
        -------
        dict or None

        Raises
        ------
        NetBoxClientError
            On API failure.
        """
        self.log.debug(
            "get_interface_by_name device_id=%s name=%r", device_id, interface_name
        )
        try:
            recs = list(
                self.nb.dcim.interfaces.filter(
                    device_id=device_id, name=interface_name
                )
            )
            return self._to_dict(recs[0]) if recs else None
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"get_interface_by_name: lookup failed for "
                f"{interface_name!r} on device_id={device_id}: {exc}"
            ) from exc

    def update_interface_state_fields(
        self,
        device_id: int,
        interface_name: str,
        state_value: str,
        state_change_ts: Optional[str] = None,
    ) -> dict:
        """
        Idempotently update the ``STATE`` custom field on a NetBox interface.

        ``state_change_ts`` is accepted for backward compatibility but is no
        longer written to NetBox — the ``state_change`` custom field has been
        removed from the data model.  Pass ``None`` or omit the argument.

        Comparison
        ----------
        - Reads the current ``custom_fields["STATE"]`` from NetBox.
        - **If it matches** *state_value*: returns ``"_action": "skipped"``
          without any API write.  ``state_change`` is **not** updated.
        - **If it differs**: PATCHes both ``STATE`` and ``state_change`` in
          a single request.  All other custom fields are untouched (NetBox
          merges partial ``custom_fields`` dicts on PATCH).

        Parameters
        ----------
        device_id : int
        interface_name : str
        state_value : str
            One of ``"UP"``, ``"DOWN"``, ``"ADMIN DOWN"``, ``"UNKNOWN"``.
        state_change_ts : str
            ISO 8601 UTC timestamp written only on a state transition,
            e.g. ``"2026-05-17T14:30:00Z"``.

        Returns
        -------
        dict::

            {
                "_action":   "updated" | "skipped" | "not_found",
                "old_state": str | None,
                "new_state": str,
            }

        Raises
        ------
        NetBoxClientError
            On lookup or PATCH failure.
        """
        self.log.debug(
            "update_interface_state_fields device_id=%s iface=%r state=%r",
            device_id, interface_name, state_value,
        )
        try:
            existing = list(
                self.nb.dcim.interfaces.filter(
                    device_id=device_id, name=interface_name
                )
            )
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"update_interface_state_fields: lookup failed for "
                f"{interface_name!r} on device_id={device_id}: {exc}"
            ) from exc

        if not existing:
            self.log.warning(
                "update_interface_state_fields: %r not found on "
                "device_id=%s — skipped",
                interface_name, device_id,
            )
            return {"_action": "not_found", "old_state": None, "new_state": state_value}

        rec      = existing[0]
        rec_dict = self._to_dict(rec)
        cur_cf   = rec_dict.get("custom_fields") or {}
        old_state = cur_cf.get("STATE") or None
        cur_val   = str(old_state or "")

        if cur_val == state_value:
            self.log.debug(
                "update_interface_state_fields: %r STATE already %r — skipped",
                interface_name, state_value,
            )
            return {"_action": "skipped", "old_state": old_state, "new_state": state_value}

        try:
            rec.update({"custom_fields": {"STATE": state_value}})
            return {"_action": "updated", "old_state": old_state, "new_state": state_value}
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"update_interface_state_fields: PATCH failed for "
                f"{interface_name!r} "
                f"payload={{'STATE': {state_value!r}}}: {exc}"
            ) from exc

    # ----------------------------------------------------------------------- #
    # Device and interface custom fields                                        #
    # ----------------------------------------------------------------------- #

    def update_device_custom_fields(
        self,
        device_id: int,
        custom_fields: dict,
    ) -> dict:
        """
        Idempotent update of a device's ``custom_fields`` dict.

        Only writes to NetBox when at least one field value differs.

        Parameters
        ----------
        device_id : int
        custom_fields : dict
            Mapping of custom field slug → value.

        Returns
        -------
        dict
            Device record with ``"_action": "updated"|"skipped"``.
        """
        self.log.debug(
            "update_device_custom_fields device_id=%s fields=%s",
            device_id, list(custom_fields),
        )
        rec = self._require_device(device_id=device_id, _raw=True)
        rec_dict = self._to_dict(rec)
        cur_cf = rec_dict.get("custom_fields") or {}

        changes_needed = any(
            str(cur_cf.get(k)) != str(v) for k, v in custom_fields.items()
        )
        if not changes_needed:
            rec_dict["_action"] = "skipped"
            return rec_dict

        try:
            rec.update({"custom_fields": custom_fields})
            d = self._to_dict(rec)
            d["_action"] = "updated"
            return d
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"update_device_custom_fields(id={device_id}) failed: {exc}"
            ) from exc

    def touch_interface_last_update(
        self,
        device_id: int,
        interface_name: str,
    ) -> dict:
        """
        Set the ``if_last_update`` custom field on an interface to *now* (UTC).

        The custom field must be configured in NetBox first.  When the
        field does not exist the write is attempted and any error is
        returned to the caller.

        Returns
        -------
        dict
            Interface record with ``"_action": "updated"``.
        """
        now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            existing = list(
                self.nb.dcim.interfaces.filter(
                    device_id=device_id, name=interface_name
                )
            )
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"touch_interface_last_update: lookup failed for "
                f"{interface_name!r}: {exc}"
            ) from exc

        if not existing:
            raise NetBoxClientError(
                f"touch_interface_last_update: {interface_name!r} not found."
            )
        rec = existing[0]
        try:
            rec.update({"custom_fields": {"if_last_update": now}})
            d = self._to_dict(rec)
            d["_action"] = "updated"
            return d
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"touch_interface_last_update: update failed for "
                f"{interface_name!r}: {exc}"
            ) from exc

    def touch_ip_last_update(self, ip_id: int) -> dict:
        """
        Set the ``IP_Last_update`` custom field on an IP address to *now* (UTC).

        Parameters
        ----------
        ip_id : int
            NetBox ``ipam.ip_addresses`` primary key.

        Returns
        -------
        dict
            IP address record with ``"_action": "updated"``.
        """
        now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            rec = self.nb.ipam.ip_addresses.get(ip_id)
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"touch_ip_last_update: lookup failed for ip_id={ip_id}: {exc}"
            ) from exc

        if rec is None:
            raise NetBoxClientError(
                f"touch_ip_last_update: IP address id={ip_id} not found."
            )
        try:
            rec.update({"custom_fields": {"IP_Last_update": now}})
            d = self._to_dict(rec)
            d["_action"] = "updated"
            return d
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"touch_ip_last_update: update failed for ip_id={ip_id}: {exc}"
            ) from exc

    # ----------------------------------------------------------------------- #
    # Cable management                                                         #
    # ----------------------------------------------------------------------- #

    def interface_has_cable(self, interface_id: int) -> bool:
        """
        Return ``True`` when the interface already has a cable attached.

        Parameters
        ----------
        interface_id : int
            NetBox dcim.interface primary key.

        Raises
        ------
        NetBoxClientError
            When the interface is not found.
        """
        self.log.debug("interface_has_cable id=%s", interface_id)
        try:
            rec = self.nb.dcim.interfaces.get(interface_id)
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"interface_has_cable: lookup failed id={interface_id}: {exc}"
            ) from exc

        if rec is None:
            raise NetBoxClientError(
                f"interface_has_cable: interface id={interface_id} not found."
            )
        return self._to_dict(rec).get("cable") is not None

    def ensure_cable(
        self,
        interface_a_id: int,
        interface_b_id: int,
        cable_type: Optional[str] = None,
    ) -> dict:
        """
        Create a cable between two interfaces.

        **The caller is responsible for verifying neither interface already
        has a cable** (see :meth:`interface_has_cable`).  This method will
        raise :class:`NetBoxClientError` if the NetBox API rejects the
        request (e.g. due to an existing cable it detects server-side).

        Parameters
        ----------
        interface_a_id : int
        interface_b_id : int
        cable_type : str, optional
            NetBox cable type slug (e.g. ``"multi mode om3"``,
            ``"single mode"``).  When ``None`` the ``type`` field is
            omitted from the payload so NetBox applies its own default.

        Returns
        -------
        dict
            Created cable record with ``"_action": "created"``.
        """
        self.log.debug(
            "ensure_cable a=%s b=%s type=%r",
            interface_a_id, interface_b_id, cable_type,
        )
        payload: dict = {
            "a_terminations": [
                {"object_type": "dcim.interface", "object_id": interface_a_id}
            ],
            "b_terminations": [
                {"object_type": "dcim.interface", "object_id": interface_b_id}
            ],
            "status": "connected",
        }
        if cable_type:
            payload["type"] = cable_type
        try:
            rec = self.nb.dcim.cables.create(payload)
            d = self._to_dict(rec)
            d["_action"] = "created"
            return d
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"ensure_cable({interface_a_id}, {interface_b_id}) failed: {exc}"
            ) from exc

    def get_interface_cable_info(self, interface_id: int) -> Optional[dict]:
        """
        Return cable and peer-endpoint information for an interface.

        Uses the detail endpoint (``dcim.interfaces.get``) so that the
        ``link_peers`` field — which lists the interface(s) on the other end
        of the attached cable — is fully populated.

        Parameters
        ----------
        interface_id : int
            NetBox dcim.interface primary key.

        Returns
        -------
        dict or None
            ``None`` when no cable is attached.  Otherwise::

                {
                    "cable_id":  int,        # NetBox dcim.cables PK
                    "peer_ids":  list[int],  # interface IDs on the far end
                }

        Raises
        ------
        NetBoxClientError
            On API failure.
        """
        self.log.debug("get_interface_cable_info id=%s", interface_id)
        try:
            rec = self.nb.dcim.interfaces.get(interface_id)
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"get_interface_cable_info: lookup failed id={interface_id}: {exc}"
            ) from exc

        if rec is None:
            raise NetBoxClientError(
                f"get_interface_cable_info: interface id={interface_id} not found."
            )

        rec_dict = self._to_dict(rec)
        cable    = rec_dict.get("cable")
        if not cable:
            return None

        cable_id = (
            cable.get("id") if isinstance(cable, dict) else int(cable)
        )

        # link_peers is a list of the interfaces directly attached via cable.
        peers    = rec_dict.get("link_peers") or []
        peer_ids = [
            int(p["id"]) for p in peers
            if isinstance(p, dict) and p.get("id") is not None
        ]

        return {"cable_id": cable_id, "peer_ids": peer_ids}

    def delete_cable(self, cable_id: int) -> None:
        """
        Delete a NetBox cable by primary key.

        Both endpoints of the cable are released when the cable is deleted.

        Parameters
        ----------
        cable_id : int
            NetBox dcim.cables primary key.

        Raises
        ------
        NetBoxClientError
            On API failure.
        """
        self.log.debug("delete_cable id=%s", cable_id)
        try:
            rec = self.nb.dcim.cables.get(cable_id)
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"delete_cable: lookup failed id={cable_id}: {exc}"
            ) from exc

        if rec is None:
            self.log.debug("delete_cable: id=%s already absent", cable_id)
            return

        try:
            ok = rec.delete()
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"delete_cable(id={cable_id}) failed: {exc}"
            ) from exc

        if not ok:
            raise NetBoxClientError(
                f"delete_cable(id={cable_id}): API returned false"
            )

    def ensure_ip_on_interface(
        self,
        ip_cidr: str,
        device_id: int,
        interface_name: str,
        vrf_id: Optional[int] = None,
    ) -> dict:
        """
        Create (or confirm) a NetBox IP address and assign it to an interface.

        Idempotent
        ----------
        - IP exists, correct interface, correct VRF → ``"skipped"``.
        - IP exists, correct interface, **wrong VRF** → controlled delete +
          recreate with the correct VRF and all preserved metadata
          (``"created"``).
        - IP exists, wrong interface, correct VRF → update assignment
          (``"updated"``).
        - IP exists, wrong interface, wrong VRF → delete + recreate on the
          correct interface with the correct VRF (``"created"``).
        - IP does not exist → create with VRF and assign it (``"created"``).

        Parameters
        ----------
        ip_cidr : str
            Host address with prefix length, e.g. ``"192.168.20.1/24"``.
        device_id : int
            NetBox device primary key that owns the interface.
        interface_name : str
            Exact interface name as it appears in NetBox, e.g. ``"Vlan20"``.
        vrf_id : int, optional
            NetBox VRF primary key.  ``None`` means the global routing table.
            When supplied, an existing IP in a different VRF will be detected
            as a mismatch and safely deleted + recreated.

        Returns
        -------
        dict
            IP address record plus ``"_action": "created"|"updated"|"skipped"``.

        Raises
        ------
        NetBoxClientError
            When the interface cannot be found or the API call fails.
        """
        self.log.debug(
            "ensure_ip_on_interface ip=%r device_id=%s iface=%r vrf_id=%s",
            ip_cidr, device_id, interface_name, vrf_id,
        )

        # ── Resolve the interface record ───────────────────────────────────
        try:
            iface_recs = list(
                self.nb.dcim.interfaces.filter(
                    device_id=device_id, name=interface_name
                )
            )
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"ensure_ip_on_interface: interface lookup failed for "
                f"{interface_name!r} on device_id={device_id}: {exc}"
            ) from exc

        if not iface_recs:
            raise NetBoxClientError(
                f"ensure_ip_on_interface: interface {interface_name!r} not found "
                f"on device_id={device_id} — ensure the interface exists first."
            )
        iface_id = iface_recs[0].id

        # ── Check for an existing IP address record ────────────────────────
        try:
            existing_ips = list(self.nb.ipam.ip_addresses.filter(address=ip_cidr))
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"ensure_ip_on_interface: IP lookup failed for {ip_cidr!r}: {exc}"
            ) from exc

        if existing_ips:
            ip_rec  = existing_ips[0]
            ip_dict = self._to_dict(ip_rec)

            # ── Evaluate assignment and VRF ────────────────────────────────
            assigned_obj  = ip_dict.get("assigned_object")
            assigned_type = ip_dict.get("assigned_object_type", "")
            assigned_id   = (
                assigned_obj.get("id")
                if isinstance(assigned_obj, dict)
                else getattr(assigned_obj, "id", None)
            )
            cur_vrf_id = self._extract_nested_id(ip_dict.get("vrf"))

            correct_iface = (
                "interface" in str(assigned_type).lower()
                and assigned_id == iface_id
            )
            correct_vrf = cur_vrf_id == vrf_id   # None == None is valid (global)

            # Perfect match — nothing to do.
            if correct_iface and correct_vrf:
                self.log.debug(
                    "ensure_ip_on_interface: %r already assigned to %r "
                    "with correct VRF — skipped",
                    ip_cidr, interface_name,
                )
                ip_dict["_action"] = "skipped"
                return ip_dict

            # VRF mismatch — safest recovery is delete + recreate.
            if not correct_vrf:
                self.log.warning(
                    "ensure_ip_on_interface: IP %r exists in VRF id=%s "
                    "but target VRF id=%s — performing controlled recreate",
                    ip_cidr, cur_vrf_id, vrf_id,
                )
                return self._recreate_ip_with_correct_vrf(
                    ip_rec=ip_rec,
                    ip_dict=ip_dict,
                    ip_cidr=ip_cidr,
                    new_vrf_id=vrf_id,
                    iface_id=iface_id,
                )

            # Wrong interface but correct VRF — reassign in-place.
            self.log.info(
                "ensure_ip_on_interface: Assigning VRF %r to IP %r → %r",
                vrf_id, ip_cidr, interface_name,
            )
            try:
                ip_rec.update({
                    "assigned_object_type": "dcim.interface",
                    "assigned_object_id":   iface_id,
                })
                d = self._to_dict(ip_rec)
                d["_action"] = "updated"
                return d
            except pynetbox.RequestError as exc:
                raise NetBoxClientError(
                    f"ensure_ip_on_interface: update failed for {ip_cidr!r}: {exc}"
                ) from exc

        # ── Create the IP address and assign it ────────────────────────────
        if vrf_id is not None:
            self.log.info(
                "ensure_ip_on_interface: Assigning VRF id=%s to IP %r",
                vrf_id, ip_cidr,
            )
        self.log.debug(
            "ensure_ip_on_interface: creating %r and assigning to %r vrf_id=%s",
            ip_cidr, interface_name, vrf_id,
        )
        payload: dict = {
            "address":              ip_cidr,
            "assigned_object_type": "dcim.interface",
            "assigned_object_id":   iface_id,
            "status":               "active",
        }
        if vrf_id is not None:
            payload["vrf"] = vrf_id
        try:
            ip_rec = self.nb.ipam.ip_addresses.create(payload)
            d = self._to_dict(ip_rec)
            d["_action"] = "created"
            return d
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"ensure_ip_on_interface: create failed for {ip_cidr!r}: {exc}"
            ) from exc

    def _recreate_ip_with_correct_vrf(
        self,
        ip_rec: Any,
        ip_dict: dict,
        ip_cidr: str,
        new_vrf_id: Optional[int],
        iface_id: int,
    ) -> dict:
        """
        Delete an IP address record and recreate it with the correct VRF.

        All restorable metadata (DNS name, description, role, status, tenant,
        tags, custom fields, nat_inside) is preserved via :meth:`_snapshot_ip`.
        The new record is assigned to *iface_id* with *new_vrf_id*.

        Parameters
        ----------
        ip_rec
            Raw pynetbox Record (needed for ``.delete()``).
        ip_dict : dict
            Already-converted dict of the same record.
        ip_cidr : str
            The address string (used for the recreated record).
        new_vrf_id : int or None
            Target VRF primary key (``None`` = global table).
        iface_id : int
            Target interface primary key.

        Returns
        -------
        dict
            Newly created IP record with ``"_action": "created"``.

        Raises
        ------
        NetBoxClientError
            When deletion or recreation fails.
        """
        ip_id = ip_dict.get("id")
        snap  = self._snapshot_ip(ip_dict)

        self.log.warning(
            "_recreate_ip_with_correct_vrf: Deleting IP id=%s address=%r",
            ip_id, ip_cidr,
        )
        try:
            ip_rec.delete()
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"_recreate_ip_with_correct_vrf: delete failed for "
                f"id={ip_id}: {exc}"
            ) from exc

        # Build recreation payload from snapshot, then override VRF + assignment
        recreate_payload = dict(snap)
        recreate_payload.update({
            "address":              ip_cidr,
            "assigned_object_type": "dcim.interface",
            "assigned_object_id":   iface_id,
        })
        recreate_payload.setdefault("status", "active")

        # Apply the correct VRF (or explicitly clear it for global)
        if new_vrf_id is not None:
            recreate_payload["vrf"] = new_vrf_id
        else:
            recreate_payload.pop("vrf", None)

        self.log.warning(
            "_recreate_ip_with_correct_vrf: Recreating %r with vrf_id=%s "
            "on iface_id=%s",
            ip_cidr, new_vrf_id, iface_id,
        )
        try:
            new_rec = self.nb.ipam.ip_addresses.create(recreate_payload)
            d = self._to_dict(new_rec)
            d["_action"] = "created"
            return d
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"_recreate_ip_with_correct_vrf: recreate failed for "
                f"{ip_cidr!r} payload={recreate_payload}: {exc}"
            ) from exc

    def reassign_ip_to_interface(
        self,
        ip_id: int,
        interface_id: int,
    ) -> dict:
        """
        Reassign an existing IP address record to a different interface.

        Used during interface relocation to move IPs from the old (deleted)
        interface to the newly recreated one, preserving all other IP fields.

        Parameters
        ----------
        ip_id : int
            NetBox IP address primary key.
        interface_id : int
            NetBox interface primary key to assign the IP to.

        Returns
        -------
        dict
            Updated IP address record with ``"_action": "updated"``.

        Raises
        ------
        NetBoxClientError
            If the IP is not found or the update fails.
        """
        self.log.debug(
            "reassign_ip_to_interface ip_id=%s iface_id=%s", ip_id, interface_id
        )
        try:
            rec = self.nb.ipam.ip_addresses.get(ip_id)
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"reassign_ip_to_interface: IP lookup for id={ip_id} failed: {exc}"
            ) from exc

        if rec is None:
            raise NetBoxClientError(
                f"reassign_ip_to_interface: IP id={ip_id} not found."
            )

        try:
            rec.update({
                "assigned_object_type": "dcim.interface",
                "assigned_object_id":   interface_id,
            })
            d = self._to_dict(rec)
            d["_action"] = "updated"
            return d
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"reassign_ip_to_interface(ip_id={ip_id}, "
                f"iface_id={interface_id}) failed: {exc}"
            ) from exc

    def clear_ip_interface_assignment(self, ip_id: int) -> dict:
        """
        Remove the interface assignment from an IP address record without
        deleting the record itself.

        Sets ``assigned_object_type`` and ``assigned_object_id`` to ``None``
        so the IP is preserved in NetBox (audit trail, potential re-use) but
        is no longer associated with any interface.

        Used by :func:`_purge_stale_ip_assignments` in
        ``sync_netbox_interfaces.py`` to clear IPs that are assigned to an
        interface in NetBox but are absent from the live device configuration.

        Parameters
        ----------
        ip_id : int
            NetBox IP address primary key.

        Returns
        -------
        dict
            ``{"_action": "cleared", "id": ip_id}``

        Raises
        ------
        NetBoxClientError
            When the IP record is not found or the update fails.
        """
        self.log.debug("clear_ip_interface_assignment ip_id=%s", ip_id)
        try:
            rec = self.nb.ipam.ip_addresses.get(ip_id)
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"clear_ip_interface_assignment: IP lookup id={ip_id} failed: {exc}"
            ) from exc

        if rec is None:
            raise NetBoxClientError(
                f"clear_ip_interface_assignment: IP id={ip_id} not found."
            )

        try:
            rec.update({
                "assigned_object_type": None,
                "assigned_object_id":   None,
            })
            return {"_action": "cleared", "id": ip_id}
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"clear_ip_interface_assignment(ip_id={ip_id}) failed: {exc}"
            ) from exc

    def get_ip_full_record(self, ip_id: int) -> dict:
        """
        Return the complete NetBox IP address record as a plain dict.

        All fields are included — description, dns_name, status, role,
        tenant, vrf, tags, custom_fields, comments, nat_inside,
        nat_outside — so the caller can create an identical record after
        a delete/recreate operation.

        Raises
        ------
        NetBoxClientError
            When the record is not found or the API call fails.
        """
        self.log.debug("get_ip_full_record ip_id=%s", ip_id)
        try:
            rec = self.nb.ipam.ip_addresses.get(ip_id)
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"get_ip_full_record: lookup id={ip_id} failed: {exc}"
            ) from exc
        if rec is None:
            raise NetBoxClientError(f"get_ip_full_record: id={ip_id} not found")
        return self._to_dict(rec)

    def update_ip_address_fields(self, ip_id: int, fields: dict) -> dict:
        """
        PATCH arbitrary fields on an existing IP address record.

        *fields* may include ``address`` (to correct the prefix length),
        ``assigned_object_type``, ``assigned_object_id``, ``description``,
        ``dns_name``, ``vrf``, ``status``, ``role``, ``tenant``, ``tags``,
        ``custom_fields``, etc.

        Returns the updated record dict with ``"_action": "updated"``.

        Raises
        ------
        NetBoxClientError
            When the record is not found or the PATCH fails.
        """
        self.log.debug("update_ip_address_fields ip_id=%s fields=%s", ip_id, list(fields))
        try:
            rec = self.nb.ipam.ip_addresses.get(ip_id)
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"update_ip_address_fields: lookup id={ip_id} failed: {exc}"
            ) from exc
        if rec is None:
            raise NetBoxClientError(f"update_ip_address_fields: id={ip_id} not found")
        try:
            rec.update(fields)
            d = self._to_dict(rec)
            d["_action"] = "updated"
            return d
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"update_ip_address_fields(ip_id={ip_id}): {exc}"
            ) from exc

    def delete_ip_address(self, ip_id: int) -> bool:
        """
        Delete an IP address record by primary key.

        Returns ``True`` on success, ``False`` when the record does not
        exist (idempotent).

        Raises
        ------
        NetBoxClientError
            When the API call fails for any reason other than not-found.
        """
        self.log.debug("delete_ip_address ip_id=%s", ip_id)
        try:
            rec = self.nb.ipam.ip_addresses.get(ip_id)
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"delete_ip_address: lookup id={ip_id} failed: {exc}"
            ) from exc
        if rec is None:
            return False
        try:
            rec.delete()
            return True
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"delete_ip_address(ip_id={ip_id}): {exc}"
            ) from exc

    def create_ip_address(self, payload: dict) -> dict:
        """
        Create an IP address record from *payload*.

        *payload* must include at minimum ``address``.
        All other standard fields (``assigned_object_type``,
        ``assigned_object_id``, ``vrf``, ``description``, ``dns_name``,
        ``status``, ``role``, ``tenant``, ``tags``, ``custom_fields``)
        are passed through unchanged.

        Returns the new record dict with ``"_action": "created"``.

        Raises
        ------
        NetBoxClientError
            When the API call fails.
        """
        self.log.debug("create_ip_address address=%r", payload.get("address"))
        try:
            rec = self.nb.ipam.ip_addresses.create(payload)
            d   = self._to_dict(rec)
            d["_action"] = "created"
            return d
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"create_ip_address({payload.get('address', '?')!r}): {exc}"
            ) from exc

    def find_ips_by_host_address(self, host_ip: str) -> list:
        """
        Return all IP address records whose host part equals *host_ip*,
        regardless of prefix length.

        E.g. querying ``"10.1.1.1"`` returns records for ``"10.1.1.1/24"``,
        ``"10.1.1.1/32"``, etc.

        This is used to detect subnet-mask mismatches: the live device
        reports ``10.1.1.1/24`` but NetBox stores ``10.1.1.1/32``.

        Returns a list of plain dicts (``_to_dict`` applied to each record).

        Raises
        ------
        NetBoxClientError
            On API failure.
        """
        self.log.debug("find_ips_by_host_address host=%r", host_ip)
        try:
            recs = list(self.nb.ipam.ip_addresses.filter(address=host_ip))
            return [self._to_dict(r) for r in recs]
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"find_ips_by_host_address({host_ip!r}): {exc}"
            ) from exc

    def get_ip_by_address(self, address: str) -> Optional[dict]:
        """
        Return the first NetBox IP address record whose ``address`` field
        matches *address* exactly (including prefix length), or ``None``.

        Parameters
        ----------
        address : str
            CIDR address string, e.g. ``"10.1.2.1/24"`` or ``"10.1.2.1/32"``.

        Returns
        -------
        dict or None

        Raises
        ------
        NetBoxClientError
            On API failure.
        """
        self.log.debug("get_ip_by_address %r", address)
        try:
            recs = list(self.nb.ipam.ip_addresses.filter(address=address))
            return self._to_dict(recs[0]) if recs else None
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"get_ip_by_address({address!r}) failed: {exc}"
            ) from exc

    def delete_ip(self, ip_id: int) -> None:
        """
        Delete an IP address record by primary key.

        Raises
        ------
        NetBoxClientError
            If the record is not found, cannot be deleted, or the API call
            fails (including dependency conflicts).
        """
        self.log.debug("delete_ip id=%s", ip_id)
        try:
            rec = self.nb.ipam.ip_addresses.get(ip_id)
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"delete_ip: lookup for id={ip_id} failed: {exc}"
            ) from exc

        if rec is None:
            self.log.debug("delete_ip: id=%s already absent", ip_id)
            return

        try:
            ok = rec.delete()
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"delete_ip(id={ip_id}) failed: {exc}"
            ) from exc

        if not ok:
            raise NetBoxClientError(
                f"delete_ip(id={ip_id}): API returned false"
            )

    def create_ip(self, payload: dict) -> dict:
        """
        Create an IP address record from *payload*.

        Parameters
        ----------
        payload : dict
            Must include ``"address"``.  Any additional fields (``vrf``,
            ``tenant``, ``status``, ``dns_name``, ``description``,
            ``assigned_object_type``, ``assigned_object_id``, etc.) are
            forwarded to the API as-is.

        Returns
        -------
        dict
            The newly created IP address record.

        Raises
        ------
        NetBoxClientError
            On missing required fields or API failure.
        """
        self._validate_payload(payload, required=["address"], context="create_ip")
        self.log.debug("create_ip address=%r", payload.get("address"))
        try:
            rec = self.nb.ipam.ip_addresses.create(payload)
            return self._to_dict(rec)
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"create_ip failed (address={payload.get('address')!r}): {exc}"
            ) from exc

    # ----------------------------------------------------------------------- #
    # FHRP group management                                                    #
    # ----------------------------------------------------------------------- #

    @staticmethod
    def _snapshot_ip(ip_rec: dict) -> dict:
        """
        Extract all re-creatable fields from an IP address record dict.

        Excludes read-only / auto-populated fields and fields that are set
        separately during recreation (``address``, assignment fields).

        Choice fields (``status``, ``role``) are unwrapped from
        ``{"value": "...", "label": "..."}`` to the plain value string.
        FK fields (``vrf``, ``tenant``, ``nat_inside``) are reduced to their
        integer IDs.  Tags are reduced to a list of ``{"slug": "..."}``
        objects as NetBox's API requires on write.

        Parameters
        ----------
        ip_rec : dict
            Plain dict from ``_to_dict()``.

        Returns
        -------
        dict
            Payload-ready dict suitable for ``create_ip``.
        """
        _SKIP: Set[str] = {
            "id", "url", "display", "created", "last_updated", "_action",
            "family",                       # auto-detected from address
            "assigned_object",              # nested read-only, set via _type/_id
            "assigned_object_type",         # caller sets these explicitly
            "assigned_object_id",
            "nat_outside",                  # reverse relation — not settable
        }
        snap: dict = {}
        for key, val in ip_rec.items():
            if key in _SKIP or val is None:
                continue
            if key == "tags" and isinstance(val, list):
                slugs = [
                    {"slug": item["slug"]}
                    for item in val
                    if isinstance(item, dict) and "slug" in item
                ]
                if slugs:
                    snap["tags"] = slugs
            elif isinstance(val, dict):
                if "value" in val:
                    snap[key] = val["value"]   # choice field → scalar
                elif "id" in val:
                    snap[key] = val["id"]      # FK → integer ID
                # dicts without id/value are skipped (unresolvable nested obj)
            elif isinstance(val, list):
                ids = [
                    item["id"] if isinstance(item, dict) and "id" in item
                    else item
                    for item in val
                    if isinstance(item, (int, dict))
                ]
                if ids:
                    snap[key] = ids
            else:
                snap[key] = val
        return snap

    @staticmethod
    def _parse_duplicate_address(error_str: str) -> Optional[str]:
        """
        Extract the first CIDR address from a NetBox 400 "Duplicate IP"
        error message string.

        NetBox formats the error as::

            {'address': ['Duplicate IP address found in global table: 10.1.2.3/24']}

        Parameters
        ----------
        error_str : str
            The full stringified error (from ``str(exc)`` or ``str(exc.error)``).

        Returns
        -------
        str or None
            CIDR string (e.g. ``"10.1.2.3/24"``), or ``None`` when not found.
        """
        m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})", error_str)
        return m.group(1) if m else None

    def ensure_fhrp_group(
        self,
        protocol: str,
        group_id: int,
        vip: str,
        description: Optional[str] = None,
        dry_run: bool = False,
    ) -> dict:
        """
        Ensure an FHRP group exists in NetBox with the correct virtual IP.

        Lookup key: ``(protocol, group_id)``.  Idempotent — returns the
        existing record when already present.  The VIP is assigned as a
        NetBox IP address with ``assigned_object_type = "ipam.fhrpgroup"``.

        Parameters
        ----------
        protocol : str
            ``"hsrp"``, ``"vrrp"``, or ``"glbp"``.
        group_id : int
            FHRP group number.
        vip : str
            Virtual IP address (with or without prefix length).  A ``/32``
            suffix is appended automatically when none is present.
        description : str, optional
            Stored in the ``description`` field — used here to record the
            current operational state (e.g. ``"active"``, ``"standby"``).
        dry_run : bool
            When ``True``, VIP assignment is logged but no NetBox writes
            are made inside ``_ensure_fhrp_vip``.

        Returns
        -------
        dict
            FHRP group record with ``"_action": "created"|"updated"|"existing"``.

        Raises
        ------
        NetBoxClientError
            On API failure.
        """
        self.log.debug(
            "ensure_fhrp_group protocol=%r group_id=%s vip=%r", protocol, group_id, vip
        )
        try:
            existing = list(
                self.nb.ipam.fhrp_groups.filter(protocol=protocol, group_id=group_id)
            )
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"ensure_fhrp_group: lookup failed protocol={protocol} "
                f"group_id={group_id}: {exc}"
            ) from exc

        if existing:
            rec = existing[0]
            rec_dict = self._to_dict(rec)
            fhrp_id = rec_dict["id"]

            # Update description (carries operational state) when it changed
            changes: dict = {}
            if description is not None and rec_dict.get("description") != description:
                changes["description"] = description
            if changes:
                try:
                    rec.update(changes)
                    rec_dict = self._to_dict(rec)
                    rec_dict["_action"] = "updated"
                except pynetbox.RequestError as exc:
                    self.log.warning(
                        "ensure_fhrp_group: update failed id=%s: %s", fhrp_id, exc
                    )
                    rec_dict["_action"] = "existing"
            else:
                rec_dict["_action"] = "existing"
        else:
            # Create the FHRP group
            payload: dict = {
                "protocol": protocol,
                "group_id": group_id,
                "name":     f"{protocol.upper()}-{group_id}",
            }
            if description:
                payload["description"] = description
            self.log.debug(
                "ensure_fhrp_group: creating %s group_id=%s", protocol, group_id
            )
            try:
                rec = self.nb.ipam.fhrp_groups.create(payload)
                rec_dict = self._to_dict(rec)
                rec_dict["_action"] = "created"
            except pynetbox.RequestError as exc:
                raise NetBoxClientError(
                    f"ensure_fhrp_group: create failed protocol={protocol} "
                    f"group_id={group_id}: {exc}"
                ) from exc
            fhrp_id = rec_dict["id"]

        # Ensure the VIP is assigned to this FHRP group
        vip_cidr = vip if "/" in vip else f"{vip}/32"
        self._ensure_fhrp_vip(fhrp_id, vip_cidr, dry_run=dry_run)

        return rec_dict

    def _ensure_fhrp_vip(
        self,
        fhrp_group_id: int,
        vip_cidr: str,
        dry_run: bool = False,
    ) -> None:
        """
        Ensure *vip_cidr* is assigned to *fhrp_group_id* as a NetBox IP address.

        Idempotent.  Failures are logged as warnings (never raised) so that
        a VIP assignment problem does not prevent the FHRP group record itself
        from being returned to the caller.

        Recovery behaviour
        ------------------
        When a plain ``create`` call returns a 400 "Duplicate IP address"
        error the method attempts two escalating recovery steps before giving
        up:

        **Step 1 — non-destructive reattach**
            The conflicting IP record is looked up in NetBox.  Its
            ``assigned_object_type`` and ``assigned_object_id`` are updated
            to point at *fhrp_group_id*, and the address is normalised to the
            requested *vip_cidr* (typically ``/32``).  If this succeeds the
            method returns immediately.

        **Step 2 — controlled delete + recreate**
            When Step 1 fails (e.g. another dependency prevents the update),
            all metadata from the conflicting record is snapshotted, the
            record is deleted, and a new IP record is created with:

            - the requested *vip_cidr* address
            - assignment to *fhrp_group_id*
            - all snapshotted metadata preserved (VRF, tenant, DNS name,
              description, role, status, tags, custom_fields, nat_inside)

            If deletion fails (e.g. another IP references this one via
            ``nat_inside``), no further action is taken and an error is
            logged so the caller can investigate.

        Dry-run
        -------
        When *dry_run* is ``True`` no NetBox writes are made; intended
        actions are logged at INFO level instead.
        """
        # ── 1. Look up the exact requested address ────────────────────────
        try:
            existing_ips = list(self.nb.ipam.ip_addresses.filter(address=vip_cidr))
        except Exception as exc:
            self.log.warning(
                "_ensure_fhrp_vip: IP lookup failed for %r: %s", vip_cidr, exc
            )
            return

        # ── 2. Already correctly assigned? ────────────────────────────────
        for ip_rec in existing_ips:
            ip_d = self._to_dict(ip_rec)
            if ip_d.get("assigned_object_type") == "ipam.fhrpgroup":
                obj    = ip_d.get("assigned_object") or {}
                obj_id = (
                    obj.get("id") if isinstance(obj, dict)
                    else getattr(obj, "id", None)
                )
                if obj_id == fhrp_group_id:
                    self.log.debug(
                        "_ensure_fhrp_vip: %r already on FHRP group %s — no action",
                        vip_cidr, fhrp_group_id,
                    )
                    return

        # ── 3. Exact address exists but is on a different object ──────────
        #       Step 1: try non-destructive reattach first.
        if existing_ips:
            ip_d   = self._to_dict(existing_ips[0])
            ip_id  = ip_d.get("id")
            cur_assignment = ip_d.get("assigned_object_type") or "unassigned"

            self.log.info(
                "_ensure_fhrp_vip: Attempting to reattach existing IP %r "
                "(id=%s, currently %s) to FHRP group %s",
                vip_cidr, ip_id, cur_assignment, fhrp_group_id,
            )

            if dry_run:
                self.log.info(
                    "DRY-RUN _ensure_fhrp_vip: would reattach %r "
                    "(id=%s) → FHRP group %s",
                    vip_cidr, ip_id, fhrp_group_id,
                )
                return

            try:
                existing_ips[0].update({
                    "assigned_object_type": "ipam.fhrpgroup",
                    "assigned_object_id":   fhrp_group_id,
                })
                self.log.info(
                    "_ensure_fhrp_vip: Successfully reattached IP %r "
                    "(id=%s) to FHRP group %s",
                    vip_cidr, ip_id, fhrp_group_id,
                )
                return
            except pynetbox.RequestError as exc:
                self.log.warning(
                    "_ensure_fhrp_vip: Step 1 reattach failed for %r "
                    "(id=%s): %s — proceeding to controlled recreation",
                    vip_cidr, ip_id, exc,
                )
                self._recover_fhrp_vip_duplicate(
                    fhrp_group_id=fhrp_group_id,
                    vip_cidr=vip_cidr,
                    conflicting_rec=ip_d,
                    dry_run=dry_run,
                )
                return

        # ── 4. Address not in NetBox at all — create it ───────────────────
        if dry_run:
            self.log.info(
                "DRY-RUN _ensure_fhrp_vip: would create %r → FHRP group %s",
                vip_cidr, fhrp_group_id,
            )
            return

        create_payload: dict = {
            "address":              vip_cidr,
            "assigned_object_type": "ipam.fhrpgroup",
            "assigned_object_id":   fhrp_group_id,
            "status":               "active",
        }
        self.log.debug(
            "_ensure_fhrp_vip: assigning %r to FHRP group %s",
            vip_cidr, fhrp_group_id,
        )
        try:
            self.nb.ipam.ip_addresses.create(create_payload)
            return
        except pynetbox.RequestError as exc:
            error_str = str(getattr(exc, "error", exc))
            is_duplicate = "duplicate ip" in error_str.lower()

            if not is_duplicate:
                self.log.warning(
                    "_ensure_fhrp_vip: could not assign %r to group %s: %s",
                    vip_cidr, fhrp_group_id, exc,
                )
                return

            # ── 5. Duplicate IP error from create → recovery ──────────────
            conflicting_addr = self._parse_duplicate_address(error_str) or vip_cidr
            self.log.warning(
                "_ensure_fhrp_vip: Duplicate IP error for %r "
                "(conflicting record: %r). Starting recovery...",
                vip_cidr, conflicting_addr,
            )

            conflict_rec = self.get_ip_by_address(conflicting_addr)
            if conflict_rec is None:
                self.log.warning(
                    "_ensure_fhrp_vip: conflicting address %r not found in "
                    "NetBox — VIP %r assignment skipped",
                    conflicting_addr, vip_cidr,
                )
                return

            # ── Host-address validation (CRITICAL safety gate) ────────────
            # Only proceed when the conflicting record and the target VIP share
            # the same host address.  A mismatch means the 400 error was
            # triggered by an unrelated IP and we must not touch it.
            vip_host      = vip_cidr.split("/")[0]
            conflict_host = conflicting_addr.split("/")[0]

            self.log.warning(
                "_ensure_fhrp_vip: Duplicate IP detected: %s", vip_host
            )

            if vip_host != conflict_host:
                self.log.warning(
                    "_ensure_fhrp_vip: Host address mismatch — device VIP %r "
                    "vs NetBox conflicting record %r.  "
                    "Skipping modification to avoid unintended changes.",
                    vip_cidr, conflicting_addr,
                )
                return

            # Same host — log mask difference and prepare correction.
            vip_prefix      = vip_cidr.split("/")[-1]      if "/" in vip_cidr      else "32"
            conflict_prefix = conflicting_addr.split("/")[-1] if "/" in conflicting_addr else "?"
            if vip_prefix != conflict_prefix:
                self.log.info(
                    "_ensure_fhrp_vip: Device mask (/%s) differs from "
                    "NetBox (/%s), correcting...",
                    vip_prefix, conflict_prefix,
                )
            # ── End validation ─────────────────────────────────────────────

            # Step 1: try to reattach the conflicting record (non-destructive)
            conflict_id = conflict_rec.get("id")
            cur_type    = conflict_rec.get("assigned_object_type") or "unassigned"
            self.log.info(
                "_ensure_fhrp_vip: Attempting to reattach existing IP %r "
                "(id=%s, currently %s) to FHRP group %s",
                conflicting_addr, conflict_id, cur_type, fhrp_group_id,
            )
            try:
                conflict_raw = self.nb.ipam.ip_addresses.get(conflict_id)
                if conflict_raw is None:
                    raise NetBoxClientError(f"IP id={conflict_id} vanished")
                conflict_raw.update({
                    "address":              vip_cidr,   # use device-authoritative mask
                    "assigned_object_type": "ipam.fhrpgroup",
                    "assigned_object_id":   fhrp_group_id,
                })
                self.log.info(
                    "_ensure_fhrp_vip: Successfully reattached IP id=%s "
                    "%r→%r to FHRP group %s",
                    conflict_id, conflicting_addr, vip_cidr, fhrp_group_id,
                )
                return
            except (pynetbox.RequestError, NetBoxClientError) as exc2:
                self.log.warning(
                    "_ensure_fhrp_vip: Step 1 reattach failed for id=%s: %s "
                    "— proceeding to Step 2 (delete + recreate)",
                    conflict_id, exc2,
                )

            # Step 2: controlled delete + recreate with all preserved metadata
            self._recover_fhrp_vip_duplicate(
                fhrp_group_id=fhrp_group_id,
                vip_cidr=vip_cidr,
                conflicting_rec=conflict_rec,
                dry_run=dry_run,
            )

    def _recover_fhrp_vip_duplicate(
        self,
        fhrp_group_id: int,
        vip_cidr: str,
        conflicting_rec: dict,
        dry_run: bool = False,
    ) -> None:
        """
        Step 2 recovery: delete the conflicting IP record and recreate it
        assigned to *fhrp_group_id*, preserving all metadata.

        Called from ``_ensure_fhrp_vip`` after the host-address validation
        has confirmed the conflicting record has the same host as the VIP and
        both the plain create and the non-destructive reattach (Step 1) have
        failed.

        Device data is authoritative for the IP address + mask (*vip_cidr*).
        NetBox metadata (VRF, tenant, DNS name, description, role, status,
        tags, custom_fields, nat_inside) is preserved from *conflicting_rec*.

        Parameters
        ----------
        fhrp_group_id : int
        vip_cidr : str
            The device-authoritative address (e.g. ``"10.254.9.1/32"``).
        conflicting_rec : dict
            Full IP record dict of the conflicting IP (from ``_to_dict``).
        dry_run : bool
            When ``True``, log intended actions without making any writes.
        """
        conflict_id   = conflicting_rec.get("id")
        conflict_addr = conflicting_rec.get("address") or str(conflict_id)
        conflict_vrf  = conflicting_rec.get("vrf")
        conflict_type = conflicting_rec.get("assigned_object_type") or "unassigned"

        self.log.warning(
            "_ensure_fhrp_vip: Duplicate IP conflict — performing controlled "
            "recreation. Conflicting IP id=%s addr=%r (assigned to %s) "
            "will be deleted and recreated as %r → FHRP group %s",
            conflict_id, conflict_addr, conflict_type,
            vip_cidr, fhrp_group_id,
        )

        # ── a. Snapshot all restorable metadata (device is authoritative  ──
        #       for address+mask; NetBox is authoritative for everything else)
        self.log.info(
            "_ensure_fhrp_vip: Preserving metadata before delete — "
            "id=%s addr=%r",
            conflict_id, conflict_addr,
        )
        snap = self._snapshot_ip(conflicting_rec)

        # ── b. Log VRF provenance ─────────────────────────────────────────
        if conflict_vrf:
            vrf_id   = (
                conflict_vrf.get("id") if isinstance(conflict_vrf, dict)
                else conflict_vrf
            )
            vrf_name = (
                conflict_vrf.get("name") if isinstance(conflict_vrf, dict)
                else str(conflict_vrf)
            )
            self.log.info(
                "_ensure_fhrp_vip: Preserving VRF %r (id=%s) from original IP",
                vrf_name, vrf_id,
            )
        else:
            self.log.info(
                "_ensure_fhrp_vip: Original IP is in the global table (no VRF)"
            )

        # ── Build the recreation payload now so dry-run can log it ────────
        recreate_payload: dict = dict(snap)
        recreate_payload.update({
            "address":              vip_cidr,
            "assigned_object_type": "ipam.fhrpgroup",
            "assigned_object_id":   fhrp_group_id,
        })
        recreate_payload.setdefault("status", "active")

        # ── Dry-run: show intent without touching NetBox ──────────────────
        if dry_run:
            self.log.info(
                "DRY-RUN _ensure_fhrp_vip: Would delete conflicting IP "
                "id=%s address=%r (mask mismatch with device VIP %r)",
                conflict_id, conflict_addr, vip_cidr,
            )
            self.log.info(
                "DRY-RUN _ensure_fhrp_vip: Would recreate IP from device "
                "data — address=%r → FHRP group %s  "
                "(preserved: vrf=%s  dns_name=%r  description=%r)",
                vip_cidr, fhrp_group_id,
                recreate_payload.get("vrf"),
                recreate_payload.get("dns_name"),
                recreate_payload.get("description"),
            )
            return

        # ── c. Delete the conflicting record ──────────────────────────────
        self.log.warning(
            "_ensure_fhrp_vip: Deleting conflicting IP %s due to mask "
            "mismatch (id=%s)",
            conflict_addr, conflict_id,
        )
        try:
            self.delete_ip(conflict_id)
        except NetBoxClientError as exc:
            self.log.error(
                "_ensure_fhrp_vip: Delete failed for IP id=%s: %s — "
                "cannot proceed with recreation; VIP %r assignment skipped",
                conflict_id, exc, vip_cidr,
            )
            return

        # ── d. Recreate from device data with all preserved metadata ───────
        self.log.warning(
            "_ensure_fhrp_vip: Recreating IP from device data — "
            "address=%r  vrf=%s  dns_name=%r  description=%r",
            vip_cidr,
            recreate_payload.get("vrf"),
            recreate_payload.get("dns_name"),
            recreate_payload.get("description"),
        )
        self.log.debug(
            "_ensure_fhrp_vip: recreate payload=%s", recreate_payload
        )

        try:
            new_rec = self.nb.ipam.ip_addresses.create(recreate_payload)
            self.log.info(
                "_ensure_fhrp_vip: Successfully reassigned IP to FHRP group — "
                "new id=%s address=%r → FHRP group %s",
                new_rec.id, vip_cidr, fhrp_group_id,
            )
        except pynetbox.RequestError as exc:
            self.log.error(
                "_ensure_fhrp_vip: Recreation failed for %r: %s — "
                "full payload was: %s",
                vip_cidr, exc, recreate_payload,
            )

    def ensure_fhrp_assignment(
        self,
        fhrp_group_id: int,
        interface_id: int,
        priority: Optional[int] = None,
    ) -> dict:
        """
        Ensure an FHRP group is assigned to a NetBox interface.

        The assignment record lives in ``ipam.fhrp_group_assignments``.
        Lookup is by ``(group, interface_type, interface_id)``.
        Idempotent: the priority field is updated when it differs from the
        stored value.

        Parameters
        ----------
        fhrp_group_id : int
            NetBox primary key of the FHRP group.
        interface_id : int
            NetBox primary key of the ``dcim.interface`` to attach to.
        priority : int, optional
            FHRP priority configured on this router.

        Returns
        -------
        dict
            Assignment record with ``"_action": "created"|"updated"|"existing"``.

        Raises
        ------
        NetBoxClientError
            On API failure.
        """
        self.log.debug(
            "ensure_fhrp_assignment group_id=%s interface_id=%s priority=%s",
            fhrp_group_id, interface_id, priority,
        )
        try:
            existing = list(
                self.nb.ipam.fhrp_group_assignments.filter(
                    group_id=fhrp_group_id,
                    interface_type="dcim.interface",
                    interface_id=interface_id,
                )
            )
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"ensure_fhrp_assignment: lookup failed group={fhrp_group_id} "
                f"iface={interface_id}: {exc}"
            ) from exc

        if existing:
            rec = existing[0]
            rec_dict = self._to_dict(rec)
            changes: dict = {}
            if priority is not None and rec_dict.get("priority") != priority:
                changes["priority"] = priority
            if changes:
                try:
                    rec.update(changes)
                    d = self._to_dict(rec)
                    d["_action"] = "updated"
                    return d
                except pynetbox.RequestError as exc:
                    raise NetBoxClientError(
                        f"ensure_fhrp_assignment: update failed: {exc}"
                    ) from exc
            rec_dict["_action"] = "existing"
            return rec_dict

        payload: dict = {
            "group":          fhrp_group_id,
            "interface_type": "dcim.interface",
            "interface_id":   interface_id,
        }
        if priority is not None:
            payload["priority"] = priority

        self.log.debug(
            "ensure_fhrp_assignment: creating group=%s iface=%s",
            fhrp_group_id, interface_id,
        )
        try:
            rec = self.nb.ipam.fhrp_group_assignments.create(payload)
            d = self._to_dict(rec)
            d["_action"] = "created"
            return d
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"ensure_fhrp_assignment: create failed group={fhrp_group_id} "
                f"iface={interface_id}: {exc}"
            ) from exc

    # ----------------------------------------------------------------------- #
    # MAC address management  (dcim.mac_addresses — NetBox 4.x+)              #
    # ----------------------------------------------------------------------- #

    @staticmethod
    def _mac_upper(mac: str) -> str:
        """Normalise MAC to uppercase colon-separated format (NetBox convention)."""
        stripped = mac.upper().replace(".", "").replace(":", "").replace("-", "")
        if len(stripped) != 12:
            return mac.upper()
        return ":".join(stripped[i:i+2] for i in range(0, 12, 2))

    def get_mac_address(self, mac: str) -> Optional[dict]:
        """
        Return the first NetBox ``dcim.mac_addresses`` record matching *mac*,
        or ``None`` when not found.

        The lookup uses the uppercase colon-separated form that NetBox stores
        internally, so any common MAC format is accepted.
        """
        mac_norm = self._mac_upper(mac)
        self.log.debug("get_mac_address mac=%r", mac_norm)
        try:
            recs = list(self.nb.dcim.mac_addresses.filter(mac_address=mac_norm))
            return self._to_dict(recs[0]) if recs else None
        except Exception as exc:
            self.log.debug("get_mac_address(%r) error: %s", mac_norm, exc)
            return None

    def create_mac_address(
        self,
        mac: str,
        interface_id: int,
        description: str = "Added via client_ip_mac.py",
        now_iso: Optional[str] = None,
    ) -> dict:
        """
        Create a new MAC address record in NetBox and assign it to an interface.

        Parameters
        ----------
        mac : str
            MAC address in any common format.
        interface_id : int
            NetBox ``dcim.interface`` primary key.
        description : str
            Stored on the MAC record.
        now_iso : str, optional
            ISO 8601 timestamp written to the ``mac_address_lastseen`` custom
            field.  When ``None`` the custom field is not included in the
            payload (NetBox leaves it unset).

        Returns
        -------
        dict
            Created MAC record with ``"_action": "created"``.
        """
        mac_norm = self._mac_upper(mac)
        payload: dict = {
            "mac_address":          mac_norm,
            "assigned_object_type": "dcim.interface",
            "assigned_object_id":   interface_id,
            "description":          description,
        }
        if now_iso:
            payload["custom_fields"] = {"mac_address_lastseen": now_iso}

        self.log.debug(
            "create_mac_address mac=%r interface_id=%s", mac_norm, interface_id
        )
        try:
            rec = self.nb.dcim.mac_addresses.create(payload)
            d = self._to_dict(rec)
            d["_action"] = "created"
            return d
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"create_mac_address: create failed for {mac_norm!r}: {exc}"
            ) from exc

    def update_mac_assignment(self, mac_id: int, interface_id: int) -> dict:
        """
        Reassign an existing MAC address record to a different interface.

        Parameters
        ----------
        mac_id : int
            NetBox ``dcim.mac_addresses`` primary key.
        interface_id : int
            NetBox ``dcim.interface`` primary key to assign to.

        Returns
        -------
        dict
            Updated MAC record with ``"_action": "reassigned"``.
        """
        self.log.debug(
            "update_mac_assignment mac_id=%s interface_id=%s", mac_id, interface_id
        )
        try:
            rec = self.nb.dcim.mac_addresses.get(mac_id)
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"update_mac_assignment: lookup failed mac_id={mac_id}: {exc}"
            ) from exc
        if rec is None:
            raise NetBoxClientError(
                f"update_mac_assignment: MAC id={mac_id} not found."
            )
        try:
            rec.update({
                "assigned_object_type": "dcim.interface",
                "assigned_object_id":   interface_id,
            })
            d = self._to_dict(rec)
            d["_action"] = "reassigned"
            return d
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"update_mac_assignment: update failed mac_id={mac_id}: {exc}"
            ) from exc

    def update_mac_lastseen(self, mac_id: int, now_iso: str) -> dict:
        """
        Write *now_iso* to the ``mac_address_lastseen`` custom field on a
        MAC address record.

        Parameters
        ----------
        mac_id : int
            NetBox ``dcim.mac_addresses`` primary key.
        now_iso : str
            ISO 8601 timezone-aware datetime string.

        Returns
        -------
        dict
            Updated MAC record with ``"_action": "refreshed"``.
        """
        self.log.debug("update_mac_lastseen mac_id=%s", mac_id)
        try:
            rec = self.nb.dcim.mac_addresses.get(mac_id)
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"update_mac_lastseen: lookup failed mac_id={mac_id}: {exc}"
            ) from exc
        if rec is None:
            raise NetBoxClientError(
                f"update_mac_lastseen: MAC id={mac_id} not found."
            )
        try:
            rec.update({"custom_fields": {"mac_address_lastseen": now_iso}})
            d = self._to_dict(rec)
            d["_action"] = "refreshed"
            return d
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"update_mac_lastseen: update failed mac_id={mac_id}: {exc}"
            ) from exc

    def ensure_mac_address(
        self,
        mac: str,
        interface_id: int,
        now_iso: str,
        description: str = "Added via client_ip_mac.py",
    ) -> dict:
        """
        Idempotently create, reassign, or refresh a MAC address record.

        Decision tree
        -------------
        1. **MAC not in NetBox** → create it, assign to *interface_id*, set
           ``mac_address_lastseen = now_iso``.
           ``"_action": "created"``

        2. **MAC found, already on correct interface** → only update
           ``mac_address_lastseen``.  No duplicate is created.
           ``"_action": "refreshed"``

        3. **MAC found, assigned to a different interface** → patch
           ``assigned_object_id`` to *interface_id*, then update
           ``mac_address_lastseen``.
           ``"_action": "reassigned"``

        Parameters
        ----------
        mac : str
            MAC address in any common format (Cisco dotted, colon, dash).
        interface_id : int
            Target ``dcim.interface`` primary key.
        now_iso : str
            ISO 8601 timezone-aware datetime for ``mac_address_lastseen``.
        description : str
            Stored on the MAC record when first created.

        Returns
        -------
        dict
            MAC record with ``"_action": "created"|"refreshed"|"reassigned"``.

        Raises
        ------
        NetBoxClientError
            On any unrecoverable API failure.
        """
        mac_norm = self._mac_upper(mac)
        self.log.debug(
            "ensure_mac_address mac=%r interface_id=%s", mac_norm, interface_id
        )

        # ── 1. Look up existing MAC record ────────────────────────────────
        try:
            existing = list(self.nb.dcim.mac_addresses.filter(mac_address=mac_norm))
        except Exception as exc:
            self.log.debug("ensure_mac_address: filter error: %s", exc)
            existing = []

        # ── 2. Not found — create ─────────────────────────────────────────
        if not existing:
            result = self.create_mac_address(
                mac=mac_norm,
                interface_id=interface_id,
                description=description,
                now_iso=now_iso,
            )
            self.log.info(
                "ensure_mac_address: created %r → interface_id=%s",
                mac_norm, interface_id,
            )
            return result

        # ── 3. Found — check current assignment ───────────────────────────
        rec      = existing[0]
        rec_dict = self._to_dict(rec)
        mac_id   = rec_dict["id"]

        cur_obj_type = str(rec_dict.get("assigned_object_type") or "")
        cur_obj_id   = rec_dict.get("assigned_object_id")

        # pynetbox sometimes returns assigned_object_id as a nested dict
        if isinstance(cur_obj_id, dict):
            cur_obj_id = cur_obj_id.get("id")

        on_correct = (
            "interface" in cur_obj_type.lower()
            and cur_obj_id == interface_id
        )

        if on_correct:
            # ── 4. Correct interface — only refresh timestamp ─────────────
            result = self.update_mac_lastseen(mac_id, now_iso)
            self.log.info(
                "ensure_mac_address: refreshed lastseen for %r on interface_id=%s",
                mac_norm, interface_id,
            )
            return result

        # ── 5. Wrong interface — reassign then refresh timestamp ──────────
        old_id = cur_obj_id
        try:
            rec.update({
                "assigned_object_type": "dcim.interface",
                "assigned_object_id":   interface_id,
                "custom_fields":        {"mac_address_lastseen": now_iso},
            })
            d = self._to_dict(rec)
            d["_action"] = "reassigned"
            self.log.info(
                "ensure_mac_address: reassigned %r from interface_id=%s → %s, "
                "lastseen updated",
                mac_norm, old_id, interface_id,
            )
            return d
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"ensure_mac_address: reassign failed for {mac_norm!r}: {exc}"
            ) from exc

    # ----------------------------------------------------------------------- #
    # Client IP tracking (client_ips interface custom field)                   #
    # ----------------------------------------------------------------------- #

    def update_interface_client_ips_cf(
        self,
        device_id: int,
        interface_name: str,
        updates: Dict[str, dict],
    ) -> dict:
        """
        Idempotently merge *updates* into the ``client_ips`` custom field on
        an interface.

        The custom field stores a JSON dict keyed by client IP address::

            {
                "10.10.10.50": {
                    "last_seen": "2026-05-14T14:20:00+00:00",
                    "mac": "a1:b2:c3:d4:e5:f6"
                },
                ...
            }

        Rules
        -----
        - Existing IPs are **updated** (timestamp + MAC refreshed).
        - IPs not in *updates* are **preserved** (merge-only, never deleted).
        - The field value is read as either a native JSON dict (CF type =
          ``json``) or a JSON string (CF type = ``text``).  Both are written
          back in the same form they were found; if writing as dict fails,
          falls back to a JSON string.

        Parameters
        ----------
        device_id : int
        interface_name : str
        updates : dict
            ``{ip_str: {"last_seen": "<ISO-8601>", "mac": "<str>"}}``

        Returns
        -------
        dict
            Interface record with ``"_action": "updated"|"skipped"``.

        Raises
        ------
        NetBoxClientError
            When the interface is not found or the API call fails.
        """
        self.log.debug(
            "update_interface_client_ips_cf device_id=%s iface=%r entries=%d",
            device_id, interface_name, len(updates),
        )
        try:
            existing = list(
                self.nb.dcim.interfaces.filter(
                    device_id=device_id, name=interface_name
                )
            )
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"update_interface_client_ips_cf: lookup failed for "
                f"{interface_name!r}: {exc}"
            ) from exc

        if not existing:
            raise NetBoxClientError(
                f"update_interface_client_ips_cf: interface {interface_name!r} "
                f"not found on device_id={device_id}."
            )

        rec     = existing[0]
        rec_dict = self._to_dict(rec)
        cur_cf  = rec_dict.get("custom_fields") or {}
        raw_val = cur_cf.get("client_ips")

        # ── Parse current value ──────────────────────────────────────────
        current: dict = {}
        use_string_encoding = False   # True when CF is a text field (JSON string)
        if raw_val is None or raw_val == "":
            pass
        elif isinstance(raw_val, dict):
            current = raw_val
        elif isinstance(raw_val, str):
            use_string_encoding = True
            try:
                current = json.loads(raw_val)
            except (json.JSONDecodeError, ValueError):
                self.log.warning(
                    "update_interface_client_ips_cf: could not parse existing "
                    "client_ips on %r — will overwrite",
                    interface_name,
                )
                current = {}

        # ── Merge ────────────────────────────────────────────────────────
        merged  = dict(current)
        changed = False
        for ip, entry in updates.items():
            if merged.get(ip) != entry:
                merged[ip] = entry
                changed = True

        if not changed:
            self.log.debug(
                "update_interface_client_ips_cf: %r — no new data, skipped",
                interface_name,
            )
            rec_dict["_action"] = "skipped"
            return rec_dict

        # ── Write back ───────────────────────────────────────────────────
        def _write(value: Any) -> dict:
            rec.update({"custom_fields": {"client_ips": value}})
            d = self._to_dict(rec)
            d["_action"] = "updated"
            return d

        try:
            value = json.dumps(merged) if use_string_encoding else merged
            return _write(value)
        except pynetbox.RequestError:
            pass

        # Fallback: try the other encoding
        try:
            value = merged if use_string_encoding else json.dumps(merged)
            return _write(value)
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"update_interface_client_ips_cf: write failed for "
                f"{interface_name!r}: {exc}"
            ) from exc

    # ----------------------------------------------------------------------- #
    # Platform management                                                      #
    # ----------------------------------------------------------------------- #

    def find_platform_by_slug(self, slug: str) -> Optional[dict]:
        """
        Return the NetBox platform record whose slug matches *slug*, or
        ``None`` when not found.

        Does **not** create a new platform.
        """
        self.log.debug("find_platform_by_slug slug=%r", slug)
        try:
            rec = self.nb.dcim.platforms.get(slug=slug)
            return self._to_dict(rec) if rec else None
        except Exception as exc:
            self.log.debug("find_platform_by_slug(%r) error: %s", slug, exc)
            return None

    def update_device_platform_by_slug(
        self,
        device_id: int,
        platform_slug: str,
    ) -> dict:
        """
        Idempotently set the ``platform`` field on a device using a slug.

        Looks up the platform object in NetBox and compares against the
        device's current platform.  Issues a PATCH only when there is a
        real change.

        Parameters
        ----------
        device_id : int
        platform_slug : str
            One of ``"ios"``, ``"iosxe"``, ``"nxos"`` (or any slug that
            exists in NetBox ``dcim.platforms``).

        Returns
        -------
        dict
            Device record with ``"_action": "updated"|"skipped"``.

        Raises
        ------
        NetBoxClientError
            When the platform slug is not found in NetBox or the API fails.
        """
        self.log.debug(
            "update_device_platform_by_slug device_id=%s slug=%r",
            device_id, platform_slug,
        )
        platform = self.find_platform_by_slug(platform_slug)
        if not platform:
            raise NetBoxClientError(
                f"update_device_platform_by_slug: platform {platform_slug!r} "
                f"not found in NetBox — create the platform object first."
            )
        platform_id = platform["id"]

        device = self._require_device(device_id=device_id)
        cur_platform = device.get("platform") or {}
        cur_id = self._extract_nested_id(cur_platform)

        if cur_id == platform_id:
            self.log.debug(
                "update_device_platform_by_slug: device %s already has platform %r — skipped",
                device_id, platform_slug,
            )
            return {"_action": "skipped", "platform": platform_slug}

        self.log.info(
            "update_device_platform_by_slug: device %s platform %r → %r",
            device_id, cur_id, platform_slug,
        )
        result = self.update_device(device_id, {"platform": platform_id})
        result["_action"] = "updated"
        return result

    # ----------------------------------------------------------------------- #
    # Prefix containment lookup (used by netbox_ap.py)                        #
    # ----------------------------------------------------------------------- #

    def get_prefixes_containing_ip(
        self,
        ip_str: str,
        site_id: Optional[int] = None,
    ) -> List[dict]:
        """
        Return all NetBox prefixes whose network range contains *ip_str*.

        Uses the NetBox ``contains`` IPAM filter so the server computes
        containment — no client-side scan of all prefixes is required.

        Parameters
        ----------
        ip_str : str
            Bare IPv4/IPv6 address, e.g. ``"10.254.175.57"`` (no mask).
        site_id : int, optional
            When provided, limit results to prefixes assigned to this site.

        Returns
        -------
        list[dict]
            List of prefix records (JSON-serialisable).  Each record includes
            the ``"prefix"`` string (e.g. ``"10.254.175.0/24"``) and the
            usual NetBox metadata fields.

        Raises
        ------
        NetBoxClientError
            On API failure.
        """
        kwargs: dict = {"contains": ip_str}
        if site_id is not None:
            kwargs["site_id"] = site_id
        try:
            recs = list(self.nb.ipam.prefixes.filter(**kwargs))
            return [self._to_dict(r) for r in recs]
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"get_prefixes_containing_ip({ip_str!r}) failed: {exc}"
            ) from exc

    # ----------------------------------------------------------------------- #
    # AP / device-type helpers (used by netbox_ap.py)                         #
    # ----------------------------------------------------------------------- #

    def get_manufacturer_by_name(self, name: str) -> Optional[dict]:
        """Return the manufacturer record whose name matches *name*, or ``None``."""
        try:
            recs = list(self.nb.dcim.manufacturers.filter(name=name))
            return self._to_dict(recs[0]) if recs else None
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"get_manufacturer_by_name({name!r}) failed: {exc}"
            ) from exc

    def ensure_manufacturer(self, name: str) -> dict:
        """
        Ensure a manufacturer named *name* exists in NetBox.

        Creates it (with an auto-slugified name) when absent.

        Returns
        -------
        dict
            Manufacturer record with ``"_action": "created"|"skipped"``.
        """
        existing = self.get_manufacturer_by_name(name)
        if existing:
            existing["_action"] = "skipped"
            return existing
        slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
        try:
            rec = self.nb.dcim.manufacturers.create({"name": name, "slug": slug})
            d = self._to_dict(rec)
            d["_action"] = "created"
            self.log.info("ensure_manufacturer: created %r (slug=%r)", name, slug)
            return d
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"ensure_manufacturer({name!r}) failed: {exc}"
            ) from exc

    def get_device_type_by_model(self, model: str) -> Optional[dict]:
        """
        Return the NetBox DeviceType that matches *model*, or ``None``.

        Search order (first hit wins):

        1. ``model`` field exact match  (``filter(model=model)``)
        2. ``model`` field case-insensitive match via full-text ``q=`` search
        3. ``part_number`` field exact match  (``filter(part_number=model)``)
        4. ``part_number`` field case-insensitive match via ``q=`` search

        Cisco AP model strings from CDP (e.g. ``"C9120AXI-B"``) are sometimes
        stored in NetBox as the ``part_number`` rather than the ``model``, so
        searching both fields is required.
        """
        model_lower = model.lower()
        try:
            # ── Pass 1: model field exact match ───────────────────────────
            recs = list(self.nb.dcim.device_types.filter(model=model))
            if recs:
                return self._to_dict(recs[0])

            # ── Pass 2: model field case-insensitive via full-text search ─
            # Save q_recs for reuse in pass 4 (part_number check).
            q_recs = list(self.nb.dcim.device_types.filter(q=model))
            for rec in q_recs:
                if rec.model.lower() == model_lower:
                    return self._to_dict(rec)

            # ── Pass 3: part_number field exact match ─────────────────────
            pn_recs = list(self.nb.dcim.device_types.filter(part_number=model))
            if pn_recs:
                self.log.debug(
                    "get_device_type_by_model: %r matched via part_number", model
                )
                return self._to_dict(pn_recs[0])

            # ── Pass 4: part_number case-insensitive in the q= result set ─
            # The full-text search in pass 2 covers part_number; check those
            # records before giving up.
            for rec in q_recs:
                pn = getattr(rec, "part_number", "") or ""
                if pn.lower() == model_lower:
                    self.log.debug(
                        "get_device_type_by_model: %r matched via part_number (q=)",
                        model,
                    )
                    return self._to_dict(rec)

            return None
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"get_device_type_by_model({model!r}) failed: {exc}"
            ) from exc

    def get_device_role_by_name(self, name: str) -> Optional[dict]:
        """Return the device role whose name matches *name*, or ``None``."""
        try:
            recs = list(self.nb.dcim.device_roles.filter(name=name))
            return self._to_dict(recs[0]) if recs else None
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"get_device_role_by_name({name!r}) failed: {exc}"
            ) from exc

    def ensure_device_role(self, name: str, color: str = "00bcd4") -> dict:
        """
        Ensure a device role named *name* exists; create it if absent.

        Returns
        -------
        dict
            Role record with ``"_action": "created"|"skipped"``.
        """
        existing = self.get_device_role_by_name(name)
        if existing:
            existing["_action"] = "skipped"
            return existing
        slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
        try:
            rec = self.nb.dcim.device_roles.create(
                {"name": name, "slug": slug, "color": color}
            )
            d = self._to_dict(rec)
            d["_action"] = "created"
            self.log.info("ensure_device_role: created %r", name)
            return d
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"ensure_device_role({name!r}) failed: {exc}"
            ) from exc

    def ensure_ap_device(
        self,
        name: str,
        device_type_id: int,
        role_id: int,
        site_id: int,
        serial: Optional[str] = None,
        tenant_id: Optional[int] = None,
        status: str = "active",
    ) -> dict:
        """
        Idempotently create or update an AP device record in NetBox.

        Decision tree
        -------------
        1. Device not found by name → create with all supplied fields.
           ``"_action": "created"``
        2. Device found → compare ``device_type``, ``serial``, ``site``,
           ``tenant``, and ``status``; patch only fields that differ.
           ``"_action": "updated"`` if any field changed, else ``"skipped"``.

        Parameters
        ----------
        name : str
            Device hostname exactly as it should appear in NetBox.
        device_type_id : int
            NetBox DeviceType primary key.
        role_id : int
            NetBox DeviceRole primary key.
        site_id : int
            NetBox Site primary key — inherited from the parent Cisco device.
        serial : str, optional
            Hardware serial number (CDP-extracted).
        tenant_id : int, optional
            NetBox Tenant primary key (inherited from parent device).
        status : str
            NetBox device status string (default ``"active"``).

        Returns
        -------
        dict
            Device record with ``"_action": "created"|"updated"|"skipped"``.
        """
        # ── Look up existing record ────────────────────────────────────────
        try:
            recs = list(self.nb.dcim.devices.filter(name=name))
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"ensure_ap_device: lookup failed for {name!r}: {exc}"
            ) from exc

        create_payload: dict = {
            "name":        name,
            "device_type": device_type_id,
            "role":        role_id,
            "site":        site_id,
            "status":      status,
        }
        if serial:
            create_payload["serial"] = serial
        if tenant_id is not None:
            create_payload["tenant"] = tenant_id

        if not recs:
            # ── Create ────────────────────────────────────────────────────
            try:
                rec = self.nb.dcim.devices.create(create_payload)
                d = self._to_dict(rec)
                d["_action"] = "created"
                self.log.info("ensure_ap_device: created %r", name)
                return d
            except pynetbox.RequestError as exc:
                raise NetBoxClientError(
                    f"ensure_ap_device: create failed for {name!r}: {exc}"
                ) from exc

        # ── Compare and update ─────────────────────────────────────────────
        rec      = recs[0]
        rec_dict = self._to_dict(rec)
        patch: dict = {}

        def _id_of(field: str) -> Optional[int]:
            val = rec_dict.get(field)
            return val.get("id") if isinstance(val, dict) else val

        if _id_of("device_type") != device_type_id:
            patch["device_type"] = device_type_id
        if _id_of("site") != site_id:
            patch["site"] = site_id
        if serial and rec_dict.get("serial") != serial:
            patch["serial"] = serial
        if tenant_id is not None and _id_of("tenant") != tenant_id:
            patch["tenant"] = tenant_id
        cur_status = rec_dict.get("status")
        cur_status_val = (
            cur_status.get("value") if isinstance(cur_status, dict) else cur_status
        )
        if cur_status_val != status:
            patch["status"] = status

        if not patch:
            rec_dict["_action"] = "skipped"
            return rec_dict

        try:
            rec.update(patch)
            d = self._to_dict(rec)
            d["_action"] = "updated"
            self.log.info(
                "ensure_ap_device: updated %r fields=%s", name, list(patch)
            )
            return d
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"ensure_ap_device: update failed for {name!r}: {exc}"
            ) from exc

    def set_device_primary_ip4(self, device_id: int, ip_id: int) -> dict:
        """
        Set ``primary_ip4`` on the device identified by *device_id*.

        Parameters
        ----------
        device_id : int
            NetBox device primary key.
        ip_id : int
            NetBox IP address primary key to set as primary IPv4.

        Returns
        -------
        dict
            Updated device record.
        """
        rec = self._require_device(device_id=device_id, _raw=True)
        cur = rec_dict = self._to_dict(rec)
        cur_ip = cur_dict = cur_rec = None
        try:
            cur_primary = rec_dict.get("primary_ip4")
            cur_ip_id = (
                cur_primary.get("id")
                if isinstance(cur_primary, dict)
                else cur_primary
            )
        except Exception:
            cur_ip_id = None

        if cur_ip_id == ip_id:
            rec_dict["_action"] = "skipped"
            return rec_dict
        try:
            rec.update({"primary_ip4": ip_id})
            d = self._to_dict(rec)
            d["_action"] = "updated"
            self.log.info(
                "set_device_primary_ip4: device_id=%s → ip_id=%s", device_id, ip_id
            )
            return d
        except pynetbox.RequestError as exc:
            raise NetBoxClientError(
                f"set_device_primary_ip4(device_id={device_id}) failed: {exc}"
            ) from exc

    def __repr__(self) -> str:
        return f"NetBoxClient(base_url={self.base_url!r})"
