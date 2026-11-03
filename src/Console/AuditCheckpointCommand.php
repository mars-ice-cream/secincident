<?php

/**
 * -------------------------------------------------------------------------
 * SecIncident — Suivi des incidents de sécurité pour GLPI
 * -------------------------------------------------------------------------
 * @license   GPLv3 https://www.gnu.org/licenses/gpl-3.0.html
 * -------------------------------------------------------------------------
 */

namespace GlpiPlugin\Secincident\Console;

use Glpi\Console\AbstractCommand;
use GlpiPlugin\Secincident\AuditCheckpoint;
use GlpiPlugin\Secincident\AuditLog;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Exporte ou vérifie un point de contrôle du journal d'audit.
 *
 * Export (une ligne JSON) vers la sortie standard, à envoyer vers un stockage
 * dont GLPI n'a pas les droits d'écriture :
 *   php bin/console plugins:secincident:audit-checkpoint | ssh cp@coffre 'cat >> secincident.jsonl'
 *
 * Vérification (dernière ligne du fichier, ou entrée standard avec « - ») :
 *   ssh cp@coffre 'tail -n 1 secincident.jsonl' | php bin/console plugins:secincident:audit-checkpoint --verify=-
 *
 * Codes de sortie : 0 cohérent, 1 anomalie, 2 point de contrôle illisible.
 */
class AuditCheckpointCommand extends AbstractCommand
{
    protected function configure()
    {
        parent::configure();
        $this->setName('plugins:secincident:audit-checkpoint');
        $this->setDescription('SecIncident: export or verify an external checkpoint of the audit log');
        $this->addOption('output', 'o', InputOption::VALUE_REQUIRED, 'Append the checkpoint (one JSON line) to this file instead of standard output');
        $this->addOption('verify', null, InputOption::VALUE_REQUIRED, 'Verify the log against this checkpoint file (JSON or JSON Lines, last line used; "-" for standard input)');
        $this->addOption('json', null, InputOption::VALUE_NONE, 'Print the verification result as JSON');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $verify = $input->getOption('verify');
        if ($verify !== null) {
            $raw = $verify === '-' ? (string) stream_get_contents(STDIN) : (is_readable($verify) ? (string) file_get_contents($verify) : '');
            $result = AuditCheckpoint::verify(AuditCheckpoint::parse($raw));
            if ($input->getOption('json')) {
                $output->writeln((string) json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
            } else {
                $this->printResult($result, $output);
            }
            if ($result['ok']) {
                return 0;
            }
            return in_array(AuditCheckpoint::ANOMALY_FORMAT, array_column($result['anomalies'], 'code'), true) ? 2 : 1;
        }

        $line = AuditCheckpoint::encode(AuditCheckpoint::export('console'));
        $file = $input->getOption('output');
        if ($file !== null) {
            if (@file_put_contents($file, $line . "\n", FILE_APPEND | LOCK_EX) === false) {
                $output->writeln('<error>Cannot write ' . $file . '</error>');
                return 2;
            }
        } else {
            $output->writeln($line);
        }
        return AuditLog::getRequestFailures() > 0 ? 1 : 0;
    }

    /**
     * @param array<string, mixed> $result
     */
    private function printResult(array $result, OutputInterface $output): void
    {
        if ($result['ok']) {
            $output->writeln('<info>Audit log consistent with the checkpoint.</info>');
        } else {
            $output->writeln('<error>ANOMALIES</error>');
            foreach ($result['anomalies'] as $anomaly) {
                $output->writeln(' - [' . $anomaly['code'] . '] ' . $anomaly['message']);
            }
        }
        if ($result['covered'] !== null) {
            $output->writeln(sprintf('Covered by the checkpoint: entries up to #%d (%s UTC), %d entries.', $result['covered']['until_id'], $result['covered']['until_date_utc'], $result['covered']['count']));
        }
        if ($result['newer'] !== null && $result['newer']['count'] > 0) {
            $output->writeln(sprintf('Newer entries verified by chaining only: #%d to #%d (%d entries, last %s UTC).', $result['newer']['from_id'], $result['newer']['to_id'], $result['newer']['count'], $result['newer']['last_date_utc']));
        }
    }
}
