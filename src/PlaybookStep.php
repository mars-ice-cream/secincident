<?php

/**
 * -------------------------------------------------------------------------
 * SecIncident — Suivi des incidents de sécurité pour GLPI 11
 * -------------------------------------------------------------------------
 * @license   GPLv3 https://www.gnu.org/licenses/gpl-3.0.html
 * -------------------------------------------------------------------------
 */

namespace GlpiPlugin\Secincident;

use CommonDBChild;
use CommonGLPI;
use Glpi\Application\View\TemplateRenderer;

/**
 * Étape d'une procédure de remédiation type.
 */
class PlaybookStep extends CommonDBChild
{
    use IntegerInputTrait;
    public static $itemtype = Playbook::class;
    public static $items_id = 'plugin_secincident_playbooks_id';

    public static $rightname = 'plugin_secincident_incident';

    public static function getTypeName($nb = 0)
    {
        return _n('Step', 'Steps', $nb, 'secincident');
    }

    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
    {
        if ($item instanceof Playbook && !$item->isNewItem()) {
            $nb = $_SESSION['glpishow_count_on_tabs']
                ? countElementsInTable(self::getTable(), [static::$items_id => $item->getID()])
                : 0;
            return self::createTabEntry(self::getTypeName(2), $nb, null, 'ti ti-list-numbers');
        }
        return '';
    }

    public static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0)
    {
        if ($item instanceof Playbook) {
            $phases = Playbook::getPhases();
            $steps  = [];
            foreach ($item->getSteps() as $step) {
                $step['phase_label'] = $phases[$step['phase']] ?? $step['phase'];
                $step['phase_color'] = Playbook::getPhaseColor((string) $step['phase']);
                $step['url']         = self::getFormURLWithID($step['id']);
                $steps[] = $step;
            }
            $max_rank = $steps === [] ? 0 : max(array_column($steps, 'position'));
            TemplateRenderer::getInstance()->display('@secincident/playbook_steps.html.twig', [
                'playbook'    => $item,
                'steps'       => $steps,
                'phases'      => $phases,
                'canedit'     => $item->canUpdateItem(),
                'fk'          => static::$items_id,
                'form_action' => self::getFormURL(),
                'next_rank'   => $max_rank + 10,
            ]);
        }
        return true;
    }

    public function showForm($ID, array $options = [])
    {
        $this->initForm($ID, $options);
        if ($this->isNewItem() && !empty($options[static::$items_id])) {
            $this->fields[static::$items_id] = (int) $options[static::$items_id];
        }
        $playbook = new Playbook();
        $playbook->getFromDB((int) ($this->fields[static::$items_id] ?? 0));
        TemplateRenderer::getInstance()->display('@secincident/playbookstep_form.html.twig', [
            'item'     => $this,
            'params'   => $options,
            'phases'   => Playbook::getPhases(),
            'playbook' => $playbook,
        ]);
        return true;
    }

    public function prepareInputForAdd($input)
    {
        if (empty($input['phase']) || !array_key_exists($input['phase'], Playbook::getPhases())) {
            $input['phase'] = 'containment';
        }
        $input['position'] = (int) ($input['position'] ?? 0);
        return parent::prepareInputForAdd($input);
    }

    public function prepareInputForUpdate($input)
    {
        if (isset($input['phase']) && !array_key_exists($input['phase'], Playbook::getPhases())) {
            $input['phase'] = 'containment';
        }
        return parent::prepareInputForUpdate($input);
    }

    public function post_addItem()
    {
        parent::post_addItem();
        AuditLog::record('create', $this, ['etape' => $this->fields['name'], 'procedure' => $this->fields[static::$items_id]]);
    }

    public function post_updateItem($history = true)
    {
        parent::post_updateItem($history);
        $diff = AuditLog::diff($this->updates, $this->oldvalues, $this->fields);
        if ($diff !== []) {
            AuditLog::record('update', $this, ['champs' => $diff]);
        }
    }

    public function post_purgeItem()
    {
        parent::post_purgeItem();
        AuditLog::record('purge', $this, ['etape' => $this->fields['name'], 'procedure' => $this->fields[static::$items_id]]);
    }
}
